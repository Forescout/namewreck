/*
Copyright (C) 2021 Forescout Technologies, Inc.

Program License

"The Program" refers to any copyrightable work licensed under this License. Each
licensee is addressed as "you."

All rights granted under this License are granted for the term of copyright on
the Program, and are irrevocable provided the stated conditions are met. This
License explicitly affirms your unlimited permission to run the unmodified
Program for personal, governmental, business or non-profit use. You are
prohibited from using the Program in derivative works for commercial purposes.
You are prohibited from modifying the Program to be used in a commercial product
or service, either alone or in conjunction with other code, either downloadable
or accessed as a service. "Derivative works" shall mean any work, whether in
source or object form, that is based on (or derived from) the Program and for
which the editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship.

You may convey verbatim copies of the Program's source code as you receive it,
in any medium, provided that you conspicuously and appropriately publish on each
copy an appropriate copyright notice; keep intact all notices stating that this
License applies to the code; keep intact all notices of the absence of any
warranty; give all recipients a copy of this License along with the Program; and
do not financially benefit from the sale or other conveyance of the Program
either alone or in conjunction with other code, downloaded or accessed as a
service.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This License does not grant permission to use the trade names, trademarks,
service marks, or product names of the Licensor, except as required for
reasonable and customary use in describing the origin of the Program and
reproducing the content of the copyright notice.
*/

import $file.generic, generic._ 
import scala.collection.mutable.Buffer
import io.shiftleft.semanticcpg.language.operatorextension.opnodes.Assignment

class DNSVulnCodeSmells {

    /*
		This function returns a Traversal that contains all potential checks for a
		compressed domain name label
    */

    private def getCompressionChecks(): Traversal[ControlStructure]  = {
        cpg.controlStructure.filter  { struct => 
            Generic.isDomainNameCompressionCheck(struct)
        }
    }

    def printBanner(): Unit = {
        val banner = """              
                     | _______      _____      _____   ___________     __      __ __________ ____________________   ____  __.
                     | \      \    /  _  \    /     \  \_   _____/ /\ /  \    /  \\______   \\_   _____/\_   ___ \ |    |/ _|
                     | /   |   \  /  /_\  \  /  \ /  \  |    __)_  \/ \   \/\/   / |       _/ |    __)_ /    \  \/ |      <  
                     |/    |    \/    |    \/    Y    \ |        \ /\  \        /  |    |   \ |        \\     \____|    |  \ 
                     |\____|__  /\____|__  /\____|__  //_______  / \/   \__/\  /   |____|_  //_______  / \______  /|____|__ \
                     |    .___\/        _\/         \/         \/            \/           \/         \/         \/         \/
                     |  __| _/  ____  _/  |_   ____    ____  _/  |_   ____  _______                                          
                     | / __ | _/ __ \ \   __\_/ __ \ _/ ___\ \   __\ /  _ \ \_  __ \                                         
                     |/ /_/ | \  ___/  |  |  \  ___/ \  \___  |  |  (  <_> ) |  | \/                                         
                     |\____ |  \___  > |__|   \___  > \___  > |__|   \____/  |__|                                            
                     |     \/      \/             \/      \/         
                     |""".stripMargin
        printf("%s\n\n", banner)
    }


    /*
    This function detects code smells that indicate that a check for a compressed
    domain name label migth violate RFC 1035.

    This is not a vulnerability per se, however this code smell might indicate the
    presence of other vulnerabilities in the DNS parser.
    */

    def invalidCompressionChecks(): Unit = {
        val compressionChecks = getCompressionChecks()

        compressionChecks.where { check =>
            check.condition.filter { condition => 
                "(0xc0\\s*\\)|0xc0\\s*&.*\\))\\s*(?:!|=)=\\s*(0xc0|12).*".r.findFirstIn(condition.code.toLowerCase).isEmpty
            }
        }.foreach { check =>
            val msg = """
                      |--------------------------------------------------------------------------------
                      |WARNING: BAD DNS COMPRESSION POINTER CHECK.
                      |--------------------------------------------------------------------------------
                      |
                      |The check shown below may be a DNS compression pointer check that does not
                      |respect [RFC 1035]. The check must ensure that both of the 2 most significant
                      |bits of the label length octet are set. This may be a sign of a "sloppy" domain
                      |name parser implementation, therefore it must be examined carefully.
                      |""".stripMargin
            Generic.printWarning(msg, check)
        }
    }


    /*
    This function detects several code smells related to the treatment of domain
    name compression pointer offsets.

    The function will issue a warning if it finds potential compression offset
    computation. The values of these offsets are often not checked in the code,
    which may lead to out-of-bounds reads and writes, as well as infinite loops.

    The function will issue a warning if the offset value may be used as a third
    argument of a memory copy call, and the value of the offset is not checked
    before making this call.

    The function will attempt to detect other unchecked copy operations related to
    the compression offset (like byte-by-byte copy operations, e.g., "ptr1*++ =
    *offset++"). Since every implementation is different, the function aims to issue
    a warning for every unchecked usage of the offset (e.g., pointer dereference or
    passing as an argument to a function).
    */
    def unsafeCompressionPointerOperations(): Unit = {

        // get all potential compression checks
        var compressionChecks = getCompressionChecks()

		compressionChecks.foreach { compCheck =>
            var taintedId: Identifier = null
            var assignments: Buffer[Assignment]  = null

            // Find all assignments dominated by a compression check.
			var dominatedByCompCheck = compCheck.condition.dominates.assignments.toSet

            // Find an assignment that might be a compression pointer offset
            // computation.
			var offsetComputation = dominatedByCompCheck.where { x => 
				x.source.ast.isIdentifier.filter { y => 
                    Generic.findIdentifier(y.code, compCheck.condition.head) != null
				}
			}.filterNot { x => 
                ".*\\s*(?:&|&=)\\s*(?:~0xc0|~0x00c0|0x3f|0x003f|0x3fff)".r.findFirstIn(x.code.toLowerCase()).isEmpty && 
                ".*\\s*(?:0xc0|0x00c0|0x3f|0x003f|0x3fff)\\s*&".r.findFirstIn(x.code.toLowerCase()).isEmpty
			}.toSet

            // If we didn't find the usual expression that computes offsets, the code might
            // ignore compressed labels and attempt to skip past them. Therefore, we need to
            // find the pointer that will jump past the compressed label.
            if (offsetComputation.size == 0) {
                offsetComputation = dominatedByCompCheck.where { x => 
                    x.code("(.*\\s*\\+=\\s*2\\s*|.*\\s*=\\s*.*\\s*\\+\\s*2\\s*|.*\\s*=\\s*2\\s*\\+\\s*.*)")
                }.toSet
            }
            // If we did find the usual expression that computes offsets, warn about it. This
            // code might have high vulnerability density, so only manual inspection will
            // allow to tell for sure.
            else {
                val msg = """
                          |--------------------------------------------------------------------------------
                          |WARNING: POTENTIAL DNS NAME COMPRESSION POINTER OFFSET COMPUTATION.
                          |--------------------------------------------------------------------------------
                          |
                          |The values of these offsets are often not checked within the code that parses
                          |DNS domain names. Depending on various implementation specifics, this may lead
                          |to the offset computation going out of bounds of the DNS packet. Therefore, each
                          |implementation that deals with compressed DNS names must be examined carefully.
                          |""".stripMargin
				Generic.printWarning(msg, offsetComputation.head)
            }

            // Try to determine a proper "source" of the data
            if (offsetComputation.size > 0) {
                val offset = offsetComputation.head
				dominatedByCompCheck -= offset

				taintedId = offset.ast.isIdentifier.head

				assignments = dominatedByCompCheck.toSeq.sortBy{ x => 
					x.lineNumber.get 
				}.filter{ x => 
					x.lineNumber.get > offset.lineNumber.get 
				}.toBuffer
            }
            else {
                taintedId = compCheck.ast.isIdentifier.head

				assignments = dominatedByCompCheck.toSeq.sortBy{ x => 
					x.lineNumber.get 
				}.toBuffer
            }

            if (taintedId != null && assignments != null) {

                // Find the affected "memcpy()" calls 
				val memcpyCalls = compCheck.method.call.filter { call =>
					Generic.memcpyCallNames.exists(call.name.toLowerCase.contains(_))
				}

				memcpyCalls.foreach { sink => 
					val sinkFlows = sink.argument(3).reachableByFlows(taintedId).toSet
					val isSinkReachable = !sinkFlows.isEmpty || (Generic.findIdentifier(taintedId.code, sink.argument(3)) != null)
					
					val argUnchecked = Generic.isExprNotChecked(sink.argument(3))

					if (isSinkReachable && argUnchecked) {
						val msg2 = """
                                   |--------------------------------------------------------------------------------
                                   |WARNING: UNCKECTED DNS NAME LABEL LENGTH USED IN A "MEMCPY()" CALL.
                                   |--------------------------------------------------------------------------------
                                   |
                                   |A value derived from an unchecked DNS name length octet has been passed into a
                                   |"memcpy()" call. This may lead to Out-of-bounds Write issues, allowing to
                                   |achieve Denial-of-Service conditions or allowing for Remote Code Execution
                                   |attacks.
                                   |""".stripMargin
						Generic.printWarning(msg2, sink)
					}
				}

                // Find the afected assignments
                while (assignments.size != 0) {
                    val currentAssignment = assignments(0)
                    val _id = Generic.findIdentifier(taintedId.code, currentAssignment.source)
                    if (_id != null) {
                        if (!Generic.isUsage(_id, currentAssignment.source)) {
                            taintedId = currentAssignment.target.ast.isIdentifier.head
                        }
                        else {
                            val id2beChecked = Generic.findIdentifier(taintedId.code, currentAssignment.source)
                            if (Generic.isExprNotChecked(id2beChecked)) {
                                val msg3 = """
                                           |--------------------------------------------------------------------------------
                                           |WARNING: USE OF A VALUE DERIVED FROM AN UNCHECKED COMPRESSION POINTER OFFSET OR
                                           |A DOMAIN LABEL LENGTH OCTET.
                                           |--------------------------------------------------------------------------------
                                           |
                                           |The statement below may use a value (e.g., through a pointer dereference or pass
                                           |into certain calls as an argument) derived from an unchecked compression pointer
                                           |offset or a domain label length octet. Depending on how it is used, it may cause
                                           |NULL pointer dereference issues, as well as out-of-bound reads and writes. This
                                           |may further lead to Denial-of-Service condtions and Remote Code Execution
                                           |attacks.
                                           |""".stripMargin
                                Generic.printWarning(msg3, currentAssignment)
                            }
                        }
                    }
                    assignments -= currentAssignment
                }
            }
		}
    }
}


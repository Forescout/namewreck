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

import io.shiftleft.semanticcpg.language._

object Generic {

    /*
        A list of relevant "memcpy" calls
    */
    val memcpyCallNames: Set[String] = Set(
        "memcpy",
        "wmemcpy",
        "memmove",
        "wmemmove",
    )


    /*
    Returns "true" if a cetain control structure might contain a domain name
    compression check within its condition
    */
    def isDomainNameCompressionCheck(struct: ControlStructure): Boolean = {
        struct.condition.ast.isLiteral.filter(_.code.toLowerCase == "0xc0").astParent.isCall.name("<operator>.and").nonEmpty
    }

    /*
    Returns "true" if the first identifier that is a part of an expression is not
    being checked before the expression may be called. 

    This function is specific to DNS compression functions, and might not work as
    expected for more generic code.
    */
    def isExprNotChecked(expr: Expression): Boolean = {
        try {
            val id2Check = expr.ast.isIdentifier.head

            val checks = expr.dominatedBy.isCall.dedup.where { x =>
                x.ast.astParent.isControlStructure
            }.filter { x =>
                Generic.findIdentifier(id2Check.code, x) != null
            }.filterNot { x =>
                Generic.isDomainNameCompressionCheck(x.ast.astParent.isControlStructure.head)
            }.whereNot { x => 
                val control = x.ast.astParent.isControlStructure
                control.code("while\\s*\\(\\s*(.*!=\\s*(0x00|0|'\\\\0')|\\*.[a-zA-Z]*)\\s*\\)")
            }

            (checks.size == 0)
        } catch {
            case _: Throwable => false
        }
    }


    /*
    Returns "true" if an identifier (node) might be "used" within an expression
    ("root"). For example, the function will return "true" if a pointer dereference
    operation has been used on the identifier, or array access, or the identifier
    has been passed as an argument into the same function (e.g., a recursive call).

    This function is specific to DNS compression functions, and might not work as
    expected for more generic code.
    */
    def isUsage(node: AstNode, root: Expression): Boolean = {
        node match {
            case id: Identifier => 
                isUsage(id.ast.astParent.head, root)
            case call: Call =>
                if (call.name == "<operator>.indirection" ||            // pointer dereference
                    call.name == "<operator>.indirectIndexAccess" ||    // array access
                    call.name.toLowerCase == "strlen" ||                // an argument to the "strlen()" call 
                    call.name == root.method.name) {                    // an argument to the recursive call
                    true
                }
                else {
                    isUsage(call.ast.astParent.head, root)
                }
            case _ => false
        }
    }


    /*
    Returns an identifier from an expression by its code string.
    Returns "null" if no such identifier exists within the expression provided.
    */
    def findIdentifier(idStr: String, root: Expression): Identifier = {
        root.astMinusRoot.isIdentifier.foreach { id =>
            if (id.code == idStr) return id 
        }
        null
    }

    /*
    Prints a warning if one of the code smells has been detected
    */
    def printWarning(message: String, expr: Expression): Unit = {
        printf("%s\n\n", message)
        printf("The location of the offending statement is shown below:\n\n")
        printf("[%s]\n", expr.method.location.filename)
        printf("||\n")
        printf("==> %s()\n", expr.method.fullName)
        printf("   ||\n")
        printf("   ===> %s: %s\n", expr.lineNumber.get, expr.code)
    }

}

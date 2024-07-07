## Challenge

The challenge allows you to send it a string of Python code, which it will parse, remove all calls, imports, TODO

<!-- TODO: what tense am I using here? -->

## TODO: title

My first step when seeing this challenge was to start looking at what components that `ast`'s parse tree could include, since I thought that there might be other parts of Python constructs that do the same thing when executed but use different syntax and therefore end up looking different in the parse tree. Looking at the grammar in the documentation for `ast` [here](https://docs.python.org/3/library/ast.html#abstract-grammar), the first thing that caught my eye was this:

```
          | Assign(expr* targets, expr value, string? type_comment)
          | TypeAlias(expr name, type_param* type_params, expr value)
          | AugAssign(expr target, operator op, expr value)
          -- 'simple' indicates that we annotate simple name without parens
          | AnnAssign(expr target, expr annotation, expr? value, int simple)
```

Nearly anything we'd want to implement would probably require an assignment, and all of those are assignments in some form, but only the first one is modified in any way by the challenge, leaving the other three free for us to use. `AugAssign` would probably have been a bit tricky to use, since that corresponds to assignments like `a += 1` and other operators that modify variables in place, and we want to have enough control to assign arbitrary values to variables. I didn't look into using `TypeAlias` during the CTF (although it likely would have worked if the Python version they were using was new enough to support it), mainly because using `AnnAssign` seemed like it would be the easiest. `AnnAssign` corresponds to assignments like `a: int = 1` and luckily for us (TODO: does this sound weird?), at runtime this behaves exactly the same as if the type annotation was removed because, as the docs for [Python's typing module](https://docs.python.org/3/library/typing.html) point out, the Python runtime doesn't enforce that type annotations are correct. It does evaluate those type annotations as expressions, so the type annotation has to be a valid expression, but we can get that by just transforming `variable = expression` into `variable: 1 = expression`, so we're now able to use any assignment we want.

## Accessing other functionality (TODO: think of better title)

Now that we have the ability to use assignments, there are 2 main limitations that we need to get around:
1. We need to be able to import additional modules to run more interesting things without using `Import` or `ImportFrom` statements.
2. We probably need to be able to call functions in order to execute whatever we can access.

I wasn't really coming up with ideas looking at the `ast` docs at this point (since I couldn't see anything obvious that would allow us to do either of those things) so I tried finding resources online on escaping Python jails and I found [this page](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes).

That has a [section on recovering `builtins`](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#builtins), which is relevant here since the challenge replaced `__builtins__` with an empty dictionary, so we wouldn't be able to use any of the functions usually in the global namespace. We don't have access to `help` or `print` or any of the other functions that they try to use in that, but they do give us access to `safe_import` and `safe_call`, so it seemed worthwhile seeing if we could use the same strategy with those functions. Temporarily commenting out the `cup = CoolDownTea().visit(cup)` line (to allow us to call `print`), adding `print` to the dictionary of local variables, and then running it with both `print(safe_import.__globals__)` and `print(safe_import.__builtins__)` confirms that we do in fact have access to both `builtins`, as well as the global variables of the challenge code. The latter in particular is relatively important since that gives us access to the `__import__` function in `builtins`, which, as the name suggests, is a function that imports a module when you give it the name of the module to import, which means that (if we can solve the second problem above of figuring out how to call functions) we've managed to solve the first problem of not being able to import modules.

## Calling Functions

The Hacktricks page above also has a [section on executing Python without calls](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-execution-without-calls). Trying out the strategies they use there, we quickly run into a new problem: the challenge only reads in one line of Python code to execute, and most of their strategies (using a decorator, defining a class with functions in it) require more than one line. We're still able to use some of the ideas there though, since one of the methods they use is to set up a class with a dunder method that executes what we want and then use some other operator to invoke that. TODO: finish this

<!-- [section on executing code without calls](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-execution-without-calls) as well as a  -->
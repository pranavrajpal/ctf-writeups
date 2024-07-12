## Challenge

This is a miscellaneous challenge allows you to send it a string of Python code which it will execute, subject to the following limitations:
- It only reads one line of your import, so your code has to fit on one line.
- It parses your code using the `ast` module, removing all instances of `Call`, `Import`, `ImportFrom`, `Assign`, or `BinOp` expressions, either replacing it with a call to a predefined function (`Call`expressions become `safe_call()`, and `Import`/`ImportFrom` statements become `safe_import()`).
- Access to `builtins` is removed by setting `__builtins__` to an empty dictionary when executing your code.


## First Steps

My first step when seeing this challenge was to start looking at what components that `ast`'s parse tree could include, since I thought that there might be other parts of Python constructs that do the same thing when executed but use different syntax and therefore end up looking different in the parse tree. Looking at the grammar in the documentation for `ast` [here](https://docs.python.org/3/library/ast.html#abstract-grammar), the first thing that caught my eye was this:

```
          | Assign(expr* targets, expr value, string? type_comment)
          | TypeAlias(expr name, type_param* type_params, expr value)
          | AugAssign(expr target, operator op, expr value)
          -- 'simple' indicates that we annotate simple name without parens
          | AnnAssign(expr target, expr annotation, expr? value, int simple)
```

Nearly anything we'd want to implement would probably require an assignment, and all of those are assignments in some form, but only the first one is modified in any way by the challenge, leaving the other three free for us to use. I ended up using `AnnAssign`, since that corresponds to assignments like `a: int = 1` and, as the docs for [Python's typing module](https://docs.python.org/3/library/typing.html) point out, the Python runtime doesn't enforce that type annotations are correct, so we can put essentially anything for the annotation. It does evaluate those type annotations as expressions, so the type annotation has to be a valid expression, but we can get that by just using `1` as the annotation (i.e. transforming `variable = expression` into `variable: 1 = expression`).

## Getting Access to `builtins`

Now that we have the ability to use assignments, there are 2 main limitations that we need to get around:
1. We need to be able to import additional modules to run more interesting things without using `Import` or `ImportFrom` statements.
2. We probably need to be able to call functions in order to execute whatever we can access.

I wasn't really coming up with ideas looking at the `ast` docs at this point (since I couldn't see anything obvious that would allow us to do either of those things) so I tried finding resources online on escaping Python jails and I found [this page](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes).

That has a [section on recovering `builtins`](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#builtins), which is relevant here since the challenge replaced `__builtins__` with an empty dictionary, and `builtins` has a few functions that would be useful to us (especially `print` so that we can debug our payload easier). They suggest using `print.__self__` or `help.__call__.__builtins__` or something like that, but that won't work since we don't have access to `help` or `print` or any of the other builtin functions that they try to use. They do, however, give us access to the functions `safe_import` and `safe_call`, and modifying their strategy to work with `safe_import` confirms that `safe_import.__builtins__` gives you `builtins`, and `safe_import.__globals__` are the globals accessible from the challenge code.

As I was looking at what `builtins` gave me access to, I also noticed that `builtins` includes `__import__`, and I knew from previous experience that (as the name suggests) it's a function which imports a given module. The fact that it's a regular function is rather important here since that means that we've found a way around problem 1 above by replacing `import x` with `safe_import.__builtins__['__import__']('x')`, assuming we can figure out how to get around problem 2 and actually call a function.

## Calling Functions

The Hacktricks page above also has a [section on executing Python without calls](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python-execution-without-calls). Trying out the strategies they use there, we quickly run into a new problem: the challenge only reads in one line of Python code to execute, and most of their strategies (like using a decorator or defining a class with functions in it) require more than one line. We're still able to use some of the ideas there though, since one of the ideas is that Python's support for operator overloading means it will execute some magic methods without call expressions, so if we can modify one of those functions we can execute it using some other language construct. As mentioned before, we can't define our own class, but we can set attributes on existing classes, and some experiments confirm that this should be possible:
```py
class A:
    pass
a = A()
# Confirming that setting magic method on instance doesn't work
a.__iadd__ = print
a += 1 # TypeError: unsupported operand type(s) for +=: 'A' and 'int'

# Setting the magic method on the class
A.__iadd__ = print
a += 1 # prints 1
```

That tells us that in order to use the above strategy we need access to an instance of a class that we can change `__iadd__` for, as well as access to that class itself.[^1] Printing out what `safe_import.__globals__` contains seems to point to the `cup` variable as a decent candidate, since it's an object of type `ast.Module`, and that globals dictionary also contains the `ast` module in `safe_import.__globals__['ast']`. Putting that together we can create a payload that prints `safe_import.__globals__` as follows (line breaks added to make it easier to read):
```py
safe_import.__globals__['ast'].Module.__iadd__: 1 = safe_import.__builtins__['print'];
safe_import.__globals__['cup'] += safe_import.__globals__
```

## Finding a better method to overwrite

One problem with the above strategy is that `__iadd__` is meant as an operator that performs an in-place update, so the return value of the function we call replaces what variable we're using the `+=` operator with (so if you printed out `a` in the above example at the end you'd see that its value was now `None`). That's a problem for us because we have a method for making calls to arbitrary functions, but we can only use it once before `cup` gets overwritten, and we need to call more than one function to get the flag, so we probably want to find a different magic method to use.

The Python docs have a list of a lot of the magic methods [here](https://docs.python.org/3/reference/datamodel.html), and given the constraints we need a magic method that:
- Isn't a binary operator (since the challenge removes those)
- Has at least one argument so that we aren't limited to calling functions with zero arguments (so that rules out unary operators)
- Isn't an in-place operator (for the reasons mentioned above)

I ended up settling on `__getitem__` since it satisfies all of the above requirements, although there would be other options that would work.

## Final Payload

After all of the above, we've found a way around nearly all of the limitations that the challenge put on us, so now we just need to get the flag. The first function I thought of trying to use was `os.system` since that lets us run arbitrary commands, so the code we want to execute is `__import__('os').system("command")` for some command of our choice, which just requires 2 uses of the above method for calling (for `__import__` and `os.system`), leading to the solution included in [solution.py](solution.py).

Running `ls` using that shows a `flag.txt` file in the current directory, and then running `cat flag.txt` gives us the flag `uiuctf{maybe_we_shouldnt_sandbox_python_2691d6c1}`.

[^1]: I realized while writing this that I could have avoided this problem entirely since if you have some instance `a` then `a.__class__` is the class of `a` (see the docs [here](https://docs.python.org/3/library/stdtypes.html#instance.__class__)) which lets us set attributes on the class fairly easily, but I didn't think of that during the CTF.

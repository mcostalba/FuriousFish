### FuriousFish

A little tool to *automagically* submit tests to Fishtest upon pushing a patch to 
your GitHub repository.

It is very simple to use, simply register with your Fishtest username here:

https://furiousfish.herokuapp.com/

And you are done. Please note that currently Fishtest username should be the same of
your GitHub account. **We don't handle different usernames.**

Write your code as usual and when you have your patch ready you add **@submit** to
your commit message:

    Simplify IID depth formula

    Restore original formula messed up during
    half-ply removal.
    
    @submit {
    Simplify IID depth formula (restore original formula, 
    messed up during half-ply removal)
    }

    bench: 8040572

After **@submit** you may want to add curly brackets with the test info that will
be displayed on the Fishtest main page.

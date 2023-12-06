# ssof-project

## Group 22
Students:
- 93585 - João Rodrigues - METI
- 93616 - Soraia Batista - METI
- 96752 - Lucas	Figueiredo - METI


## Execute

```
python ./py_analyser.py slice_1.py my_patterns.json
```

## Logic SRB 🧠

1 - Passas por uma var X e cria um multilabelling, com X associado a uma multilabel com labels vazias associadas a cada pattern já existente

2 - X passa por uma função que não aparece na pattern
	X = troll()
	Não faz nada e continua a analise

3.1 - X passa por uma função source da Pattern A
	X = srcFun()
	Criar uma label que está associada à Pattern A (a associaçao é pelo nome) com src e sanitizer vazio, adicionar ao multilabel e multilabelling

3.2 - X fica em contacto com uma var tainted
	(...)
	X = varTainted
	ou
	(...)
	X = fun(varTainted)
	Obter a src de varTainted (Combinar? Juntar? Até onde?) e fazer qq coisa com label de X

## to Do ✅
- Create __str()__ for each tool class
- Create a script to execute tests
- Add is_empty() methods to some classes
- Add no_line attribute to some classes
- Finish the add_vulnerability method in Vulnerabilities to get unsanitized_flows and consequently the combine methods [example](tests/2-expr-binary-ops.py)


- Doubts:
	- How to keep track of the sinks? The label keeps track of sources and sanitizers, but no one stores the sinks.
		- Policy, podemos ver no meio ou no fim
	- Expr corresponds to what?
	- If
		X = taintedA + tainted
		B
		sinkFun(X)
	- Faz sentido um label ter um dicionario de sources e os seus sanitizers respetivos?
		- Sim
	- Uma função "c()" tbm entra no multilabelling?
		- Nao
	- Uma src entra no multilabelling?
	- Uma sink entra no multilabelling?
	- [Neste caso](tests/1b-basic-flow.py) o label do c dava reset na ultima linha????
	- Um sanitizer limpa tudo o que estiver para trás?
		- Sim
	- output do sanitized_flows? [aqui](tests/2-expr-binary-ops.py)

- Ter 2 funçoes recursivas 1 para expressoes e outra para statements
- Reconhecer se os nos so assignments
- Escrever funçao de recursividade
- Sources tem q estar juntos com os sanitizers
- 


	
## Guideline

- Lab1: Pattern, Label, MultiLabel
- Lab2: Policy, MultiLabelling, Vulnerabilities
- Lab3: 
- Lab4: 

## Useful Links

### Ast Types
- Expressions - https://docs.python.org/3/library/ast.html#expressions

	- Constant - https://docs.python.org/3/library/ast.html#ast.Constant
	
	- Name - https://docs.python.org/3/library/ast.html#ast.Name

	- BinOp - https://docs.python.org/3/library/ast.html#ast.BinOp
	
	- UnaryOp - https://docs.python.org/3/library/ast.html#ast.UnaryOp
	
	- BoolOp - https://docs.python.org/3/library/ast.html#ast.BoolOp

	- Compare -	https://docs.python.org/3/library/ast.html#ast.Compare
	
	- Call - https://docs.python.org/3/library/ast.html#ast.Call

	- Attribute - https://docs.python.org/3/library/ast.html#ast.Attribute

- Statements - https://docs.python.org/3/library/ast.html#statements

	- Expr - https://docs.python.org/3/library/ast.html#ast.Expr

	- Assign - https://docs.python.org/3/library/ast.html#ast.Assign
	
- Control Flow - https://docs.python.org/3/library/ast.html#control-flow

	- If -	https://docs.python.org/3/library/ast.html#ast.If

	- While -	https://docs.python.org/3/library/ast.html#ast.While

### Links
- [Python Ast root Nodes](https://docs.python.org/3/library/ast.html#root-nodes)
- [Json viewer](https://jsonviewer.stack.hu/)


## Definitions

__Goal__: Detect vulnerabilities by tracking illegal flows from _sources_ to _sinks_, and analyzing whether they are processed by _sanitizers_

- __Sources__ - input functions where attackers can insert untrusted information. 

- __Sinks__ - arguments of sensitive functions or variables.

- __Sanitizers__ - special functions that can neutralize the potential vulnerability, or validate that there is none.

- __Classes__:

    - __Pattern__ - 

    - __Label__ - 

    - __Multilabel__ - 

	- __Multilabelling__ - represents a mapping from variable names to multilabels <br />
						 - Owned by: Tool <br />
						 - Has: Multilabels

    - __Policy__ - represents an information flow policy, that uses a pattern data base for recognizing illegal information flows

    - __Vulnerabilities__ -  used to collect all the illegal flows that are discovered during the analysis of the program slice 
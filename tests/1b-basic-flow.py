a="";
a=b();
c=a;
d=c;
e(d);
c="";#Duvida aqui o c cria outra entrada na label com diferente linha
f=c#Duvida aqui, linha extra
# tip: assignments propagate taintedness, and the order in which they are performed matters

f(a)#f sanitiza
e(a)#e é sink
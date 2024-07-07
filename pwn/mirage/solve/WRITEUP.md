This is a bug in turboshaft load elimination. During turboshaft reduction of
stack argument loading, if the stack slot is first loaded as a WordPtr, then 
cast to a tagged value, load elimination may eliminate the load without
accounting for the fact that the object the pointer refers to may have
been moved by the garbage collector. If garbage collection occurs between
the load and the cast, an attacker can gain a handle to freed memory in the
v8 heap.

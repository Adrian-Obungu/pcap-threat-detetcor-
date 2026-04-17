# Linear Algebra Foundations: Matrix-Vector Multiplication and Systems of Linear Equations

This document summarizes the core concepts of matrix-vector multiplication and the representation of systems of linear equations in matrix form, as discussed in the provided transcripts. These foundational linear algebra concepts are crucial for understanding the underlying mechanics of many machine learning algorithms, including those used in the Hybrid AI-Driven IDS.

## 1. Matrix-Vector Multiplication: A Linear Combination

Matrix-vector multiplication is a fundamental operation in linear algebra that provides a compact way to express linear combinations of vectors. 

**Definition:**
Given an $M \times N$ matrix $A$ with columns $A_1, A_2, \dots, A_N$, and an $N \times 1$ column vector $X$ with entries $x_1, x_2, \dots, x_N$, the product $A \times X$ is defined as the linear combination of the columns of $A$ with weights given by the entries of $X$ [1].

$$A \times X = x_1A_1 + x_2A_2 + \dots + x_NA_N$$

**Key Points:**
*   The number of columns in matrix $A$ **must** equal the number of entries in vector $X$. If $A$ is $M \times N$, then $X$ must be $N \times 1$.
*   The result of the multiplication $A \times X$ is an $M \times 1$ vector.
*   This operation can also be viewed as taking the dot product of each row of the matrix $A$ with the vector $X$ to produce the corresponding entry in the resulting vector.

**Example:**
Consider a $2 \times 3$ matrix $A$ and a $3 \times 1$ vector $X$:

$$A = \begin{pmatrix} 1 & 2 & 3 \\ 4 & 5 & 6 \end{pmatrix}, \quad X = \begin{pmatrix} 1 \\ -1 \\ 0 \end{pmatrix}$$

The product $A \times X$ is calculated as:

$$A \times X = 1 \begin{pmatrix} 1 \\ 4 \end{pmatrix} + (-1) \begin{pmatrix} 2 \\ 5 \end{pmatrix} + 0 \begin{pmatrix} 3 \\ 6 \end{pmatrix} = \begin{pmatrix} 1-2+0 \\ 4-5+0 \end{pmatrix} = \begin{pmatrix} -1 \\ -1 \end{pmatrix}$$

## 2. Systems of Linear Equations as Matrix Equations

One of the most powerful applications of matrix-vector multiplication is its ability to compactly represent systems of linear equations. Any system of linear equations can be rewritten in the form $A \times X = B$ [2].

**Transformation Process:**
Given a system of linear equations:

$$x_1 - x_2 + 2x_3 = 1$$
$$2x_1 + x_2 + x_3 = 8$$
$$x_1 + x_2 = 5$$

This system can be expressed as a vector equation, which is a linear combination of column vectors:

$$x_1 \begin{pmatrix} 1 \\ 2 \\ 1 \end{pmatrix} + x_2 \begin{pmatrix} -1 \\ 1 \\ 1 \end{pmatrix} + x_3 \begin{pmatrix} 2 \\ 1 \\ 0 \end{pmatrix} = \begin{pmatrix} 1 \\ 8 \\ 5 \end{pmatrix}$$

By the definition of matrix-vector multiplication, this is equivalent to the matrix equation $A \times X = B$, where:

$$A = \begin{pmatrix} 1 & -1 & 2 \\ 2 & 1 & 1 \\ 1 & 1 & 0 \end{pmatrix}, \quad X = \begin{pmatrix} x_1 \\ x_2 \\ x_3 \end{pmatrix}, \quad B = \begin{pmatrix} 1 \\ 8 \\ 5 \end{pmatrix}$$

**Equivalence of Solutions:**
The solutions to the matrix equation $A \times X = B$ are precisely the same as the solutions to the original system of linear equations. This means finding a vector $X$ that satisfies $A \times X = B$ is equivalent to finding a solution to the system of equations represented by the augmented matrix $[A | B]$ [2].

**Conceptual Significance:**
Thinking of a matrix $A$ as a transformation that operates on a vector $X$ to produce another vector $B$ provides a powerful geometric interpretation. The matrix $A$ transforms vectors by taking linear combinations of its columns. Solving $A \times X = B$ is asking: "Can $B$ be formed by a linear combination of the columns of $A$, and if so, what are the weights (the entries of $X$)?"

---

**References**
[1] Transcript: 1.4 Part 1 - Matrix-Vector Multiplication
[2] Transcript: 1.4 Part 2 - Systems of Linear Equations as Matrix Equations

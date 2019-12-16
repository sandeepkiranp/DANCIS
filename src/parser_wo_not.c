// CPP program to evaluate a given 
// expression where tokens are 
// separated by space. 
#include <stdio.h> 
#include <string.h>
#include <ctype.h>

typedef struct stack
{
    int stack[100];
    int n;
    int top;
}stack;

int attributes[50] = {0};

void init_stack(stack *s)
{
    s->top = 0;
    s->n = 100;
    memset(s->stack, 0, sizeof(s->stack));
}
void push(stack *s, int x)
{
    if(s->top>=s->n-1)
    {
        printf("\n\tSTACK is over flow");
         
    }
    else
    {
        s->top++;
        s->stack[s->top]=x;
    }
}

int pop(stack *s)
{
    if(s->top<=-1)
    {
        printf("\n\t Stack is under flow");
    }
    else
    {
    int x = s->stack[s->top];
        s->top--;
    return x;
    }
}

int top(stack *s)
{
    if(s->top<=-1)
    {
        printf("\n\t Stack is under flow");
    }
    else
    {
        return s->stack[s->top];
    }
}

int empty(stack *s)
{
    if(s->top == 0)
        return 1;
    else
	return 0;
}

// Function to find precedence of 
// operators. 
int precedence(char op){ 
    if(op == '|') 
        return 1; 
    if(op == '&') 
        return 2; 
    if(op == '!')
        return 3;
    return 0; 
} 

// Function to perform arithmetic operations. 
int applyOp(int a, int b, char op){ 
    switch(op){ 
        case '&': return (a && b); 
        case '|': return (a | b); 
        case '!': return !a; 
    } 
} 

// Function that returns value of 
// expression after evaluation. 
int evaluate(char * tokens){ 
    int i; 
    
    // stack to store integer values. 
    stack values; 
    
    // stack to store operators. 
    stack ops; 
    
    init_stack(&values);
    init_stack(&ops);

    for(i = 0; i < strlen(tokens); i++){ 
        
        // Current token is a whitespace, 
        // skip it. 
        if(tokens[i] == ' ') 
            continue; 
        
        // Current token is an opening 
        // brace, push it to 'ops' 
        else if(tokens[i] == '('){ 
            push(&ops, tokens[i]); 
        } 
        
        // Current token is a number, push 
        // it to stack for numbers. 
        else if(tokens[i] == 'A'){ 
            int val = 0; 
                i++;    
            // There may be more than one 
            // digits in number. 
            while(i < strlen(tokens) && 
                        isdigit(tokens[i])) 
            { 
                val = (val*10) + (tokens[i]-'0'); 
                i++; 
            } 
            
            push(&values, attributes[val]); 
        } 
        
        // Closing brace encountered, solve 
        // entire brace. 
        else if(tokens[i] == ')') 
        { 
            while(!empty(&ops) && top(&ops) != '(') 
            { 
                int val2 = top(&values); 
                pop(&values); 
                
                int val1 = top(&values); 
                pop(&values); 
                
                char op = top(&ops); 
                pop(&ops); 
                
                push(&values, applyOp(val1, val2, op)); 
            }
            
            // pop opening brace. 
            if(!empty(&ops)) 
                pop(&ops); 
        } 
        
        // Current token is an operator. 
        else
        { 
            // While top of 'ops' has same or greater 
            // precedence to current token, which 
            // is an operator. Apply operator on top 
            // of 'ops' to top two elements in values stack. 
            while(!empty(&ops) && precedence(top(&ops)) 
                                >= precedence(tokens[i])){ 
                int val2 = top(&values); 
                pop(&values); 
                
                int val1 = top(&values); 
                pop(&values); 
                
                char op = top(&ops); 
                pop(&ops); 
                
                push(&values, applyOp(val1, val2, op)); 
            } 
            
            // Push current token to 'ops'. 
            push(&ops, tokens[i]); 
        } 
    } 
    
    // Entire expression has been parsed at this 
    // point, apply remaining ops to remaining 
    // values. 
    while(!empty(&ops)){ 
        int val2 = top(&values); 
        pop(&values); 
                
        int val1 = top(&values); 
        pop(&values); 
                
        char op = top(&ops); 
        pop(&ops); 
                
        push(&values,applyOp(val1, val2, op)); 
    } 
    
    // Top of 'values' contains result, return it. 
    return top(&values); 
} 

int main() { 
    attributes[1] = 1;
    attributes[2] = 0;
    attributes[3] = 1;
    attributes[4] = 1;
    attributes[5] = 0;
    //cout << evaluate("10 + 2 * 6") << "\n"; 
    //cout << evaluate("100 * 2 + 12") << "\n"; 
    //cout << evaluate("100 * ( 2 + 12 )") << "\n"; 
    //cout << evaluate("10 + (3 - 2 ) + (100 * ( 2 + 12 ) / 14 )"); 
    //cout << evaluate("10 + (3 - 2 ) + 100"); 
    //cout << evaluate("10 + ( 3 * 4 )"); 
    printf("result = %d\n", evaluate("A2 | A2"));
    printf("result = %d\n", evaluate("A1 | A2"));
    printf("result = %d\n", evaluate("A1 & A3"));
    printf("result = %d\n", evaluate("A1 | A2 & A1"));
    printf("result = %d\n", evaluate("( A1 | A2 ) & A2"));
    return 0; 
} 

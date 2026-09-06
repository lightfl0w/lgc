#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#define O_BINARY _O_BINARY
static char *strndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}
typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;
#define ET_EXEC 2
#define EM_X86_64 62
#define EV_CURRENT 1
#define PT_LOAD 1
#define PF_R 4
#define PF_X 1
#else
#include <elf.h>
#define O_BINARY 0
#endif

static void die(const char *msg, int line) {
    fprintf(stderr, "error (line %d): %s\n", line, msg);
    exit(1);
}

#define PUSH(arr, n, cap, item) do {                                     \
    if ((n) >= (cap)) {                                                  \
        (cap) = (cap) ? (cap) * 2 : 4;                                   \
        (arr) = realloc((arr), (cap) * sizeof *(arr));                   \
    }                                                                    \
    (arr)[(n)++] = (item);                                               \
} while (0)

typedef enum {
    TOK_LET, TOK_PRINT, TOK_IF, TOK_ELSE, TOK_WHILE, TOK_RETURN, TOK_FUNC,
    TOK_SIZEOF, TOK_INT,
    TOK_IDENTIFIER, TOK_NUMBER,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH,
    TOK_AMP, TOK_LBRACKET, TOK_RBRACKET,
    TOK_ASSIGN, TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_SEMICOLON, TOK_COMMA,
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_EOF, TOK_ERROR
} TokenType;

typedef struct { TokenType type; char *text; int line; } Token;
typedef struct { const char *src; int pos, line; } Lexer;

static Token tok(TokenType t, const char *s, int len, int line) {
    Token tk = { t, strndup(s, len), line };
    return tk;
}

static const char *KWD[] = { "let", "print", "if", "else", "while", "return", "func", "sizeof", "int" };

static const uint64_t PUNCT_BIT[2] = {
    (1ULL << 33) | (1ULL << 38) | (1ULL << 40) | (1ULL << 41) | (1ULL << 42) | (1ULL << 43) |
    (1ULL << 44) | (1ULL << 45) | (1ULL << 47) | (1ULL << 59) |
    (1ULL << 60) | (1ULL << 61) | (1ULL << 62), 
    (1ULL << 27) | (1ULL << 29) | (1ULL << 59) | (1ULL << 61),              
};

static const uint64_t PAIR_BIT[2] = {
    (1ULL << 33) | (1ULL << 60) | (1ULL << 61) | (1ULL << 62), 0,
};

static const TokenType CHAR_TOK[128] = {
    ['+'] = TOK_PLUS, ['-'] = TOK_MINUS, ['*'] = TOK_STAR, ['/'] = TOK_SLASH,
    ['&'] = TOK_AMP,
    ['['] = TOK_LBRACKET, [']'] = TOK_RBRACKET,
    [';'] = TOK_SEMICOLON, [','] = TOK_COMMA,
    ['('] = TOK_LPAREN, [')'] = TOK_RPAREN, ['{'] = TOK_LBRACE, ['}'] = TOK_RBRACE,
    ['='] = TOK_ASSIGN, ['!'] = TOK_ERROR, ['<'] = TOK_LT, ['>'] = TOK_GT,
};

static const TokenType PAIR2_TOK[128] = {
    ['='] = TOK_EQ, ['!'] = TOK_NE, ['<'] = TOK_LE, ['>'] = TOK_GE,
};

static Token next_token(Lexer *lx) {
    while (isspace(lx->src[lx->pos])) {
        if (lx->src[lx->pos] == '\n') lx->line++;
        lx->pos++;
    }
    int s = lx->pos, line = lx->line;
    char c = lx->src[s];
    if (!c) return tok(TOK_EOF, "", 0, line);
    if (isalpha(c) || c == '_') {
        while (isalnum(lx->src[lx->pos]) || lx->src[lx->pos] == '_') lx->pos++;
        int len = lx->pos - s;
        for (int i = 0; i < 9; i++)
            if (len == (int)strlen(KWD[i]) && !memcmp(&lx->src[s], KWD[i], len))
                return tok(TOK_LET + i, &lx->src[s], len, line);
        return tok(TOK_IDENTIFIER, &lx->src[s], len, line);
    }
    if (isdigit(c)) {
        while (isdigit(lx->src[lx->pos])) lx->pos++;
        return tok(TOK_NUMBER, &lx->src[s], lx->pos - s, line);
    }
    lx->pos++;
    unsigned char uc = (unsigned char)c;
    if (uc >= 128 || !(PUNCT_BIT[uc >> 6] >> (uc & 63) & 1)) 
        return tok(TOK_ERROR, &lx->src[s], 1, line);
    TokenType t = CHAR_TOK[uc];
    int len = 1;
    if (lx->src[lx->pos] == '=' && (PAIR_BIT[uc >> 6] >> (uc & 63) & 1)) {
        t = PAIR2_TOK[uc];
        len = 2;
        lx->pos++;
    }
    return tok(t, &lx->src[s], len, line);
}

typedef enum {
    NODE_NUMBER, NODE_VARIABLE, NODE_BINARY, NODE_LET, NODE_PRINT,
    NODE_BLOCK, NODE_IF, NODE_WHILE, NODE_RETURN, NODE_FUNCTION, NODE_CALL,
    NODE_ADDR, NODE_DEREF, NODE_INDEX, NODE_ASSIGN, NODE_SIZEOF
} NodeType;
typedef enum { OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_EQ, OP_NE, OP_LT, OP_GT, OP_LE, OP_GE } BinOp;

typedef struct Type { uint8_t kind, len; struct Type *base; } Type;

static Type TY_INT = { 0, 0, NULL };
static Type *ty_ptr(Type *b) {
    static Type t[16]; static int n;
    t[n] = (Type){ 1, 0, b };
    return &t[n++];
}
static Type *ty_arr(int n, Type *b) {
    static Type t[16]; static int c;
    t[c] = (Type){ 2, (uint8_t)n, b };
    return &t[c++];
}
static int ty_size(Type *t) { return t->kind == 2 ? t->len * ty_size(t->base) : 8; }

typedef struct ASTNode {
    NodeType type;
    int line;
    union {
        struct { long value; } number;
        struct { char *name; } variable;
        struct { BinOp op; struct ASTNode *left, *right; } binary;
        struct { char *name; Type *ty; struct ASTNode *value; } let;
        struct { struct ASTNode *value; } print;
        struct { struct ASTNode **stmts; int count, cap; } block;
        struct { struct ASTNode *cond, *then, *else_; } if_node;
        struct { struct ASTNode *cond, *body; } while_node;
        struct { struct ASTNode *value; } return_node;
        struct { char *name; char **params; int pcount; struct ASTNode *body; } function;
        struct { char *name; struct ASTNode **args; int acount; } call;
        struct { struct ASTNode *value; } unary;
        struct { struct ASTNode *base, *index; } index;
        struct { struct ASTNode *lhs, *rhs; } assign;
    } data;
} ASTNode;

static ASTNode *node(NodeType t, int line) {
    ASTNode *n = calloc(1, sizeof *n);
    n->type = t; n->line = line;
    return n;
}

typedef struct { Token *tokens; int count, pos; Token cur; } Parser;

static void adv(Parser *p) { p->cur = p->pos < p->count ? p->tokens[p->pos++] : (Token){ TOK_EOF, NULL, 0 }; }

static void expect(Parser *p, TokenType t, const char *what) {
    if (p->cur.type != t) die(what, p->cur.line);
    adv(p);
}

static const uint8_t BINOP[TOK_ERROR + 1] = {
    [TOK_EQ] = OP_EQ | 1 << 4,  [TOK_NE] = OP_NE | 1 << 4,
    [TOK_LT] = OP_LT | 2 << 4,  [TOK_GT] = OP_GT | 2 << 4,
    [TOK_LE] = OP_LE | 2 << 4,  [TOK_GE] = OP_GE | 2 << 4,
    [TOK_PLUS] = OP_ADD | 3 << 4, [TOK_MINUS] = OP_SUB | 3 << 4,
    [TOK_STAR] = OP_MUL | 4 << 4, [TOK_SLASH] = OP_DIV | 4 << 4,
};

static ASTNode *parse_expression(Parser*);
static ASTNode *parse_statement(Parser*);
static ASTNode *parse_block(Parser*);

static Type *parse_type(Parser *p) {
    expect(p, TOK_INT, "expected type");
    Type *t = &TY_INT;
    for (;;) {
        if (p->cur.type == TOK_STAR) { adv(p); t = ty_ptr(t); }
        else if (p->cur.type == TOK_LBRACKET) {
            adv(p);
            if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
            int n = (int)atol(p->cur.text);
            adv(p);
            expect(p, TOK_RBRACKET, "expected ']'");
            t = ty_arr(n, t);
        } else break;
    }
    return t;
}

static ASTNode *parse_primary(Parser *p) {
    Token t = p->cur;
    if (t.type == TOK_NUMBER) {
        adv(p);
        ASTNode *n = node(NODE_NUMBER, t.line);
        n->data.number.value = atol(t.text);
        return n;
    }
    if (t.type == TOK_IDENTIFIER) {
        adv(p);
        if (p->cur.type != TOK_LPAREN) {
            ASTNode *n = node(NODE_VARIABLE, t.line);
            n->data.variable.name = strdup(t.text);
            return n;
        }
        adv(p);
        ASTNode *n = node(NODE_CALL, t.line);
        n->data.call.name = strdup(t.text);
        ASTNode **args = NULL;
        int ac = 0, acap = 0;
        if (p->cur.type != TOK_RPAREN)
            do {
                PUSH(args, ac, acap, parse_expression(p));
            } while (p->cur.type == TOK_COMMA && (adv(p), 1));
        expect(p, TOK_RPAREN, "expected ')'");
        n->data.call.args = args;
        n->data.call.acount = ac;
        return n;
    }
    if (t.type == TOK_LPAREN) {
        adv(p);
        ASTNode *e = parse_expression(p);
        expect(p, TOK_RPAREN, "expected ')'");
        return e;
    }
    die("syntax error", t.line);
    return NULL;
}

static ASTNode *parse_postfix(Parser *p) {
    ASTNode *n = parse_primary(p);
    while (p->cur.type == TOK_LBRACKET) {
        int line = p->cur.line;
        adv(p);
        ASTNode *i = node(NODE_INDEX, line);
        i->data.index.base = n;
        i->data.index.index = parse_expression(p);
        expect(p, TOK_RBRACKET, "expected ']'");
        n = i;
    }
    return n;
}

static ASTNode *parse_unary(Parser *p) {
    int line = p->cur.line;
    switch (p->cur.type) {
        case TOK_MINUS: {
            adv(p);
            ASTNode *zero = node(NODE_NUMBER, line);
            ASTNode *n = node(NODE_BINARY, line);
            n->data.binary.op = OP_SUB;
            n->data.binary.left = zero;
            n->data.binary.right = parse_unary(p);
            return n;
        }
        case TOK_AMP:
            adv(p);
            { ASTNode *n = node(NODE_ADDR, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_STAR:
            adv(p);
            { ASTNode *n = node(NODE_DEREF, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_SIZEOF:
            adv(p);
            { ASTNode *n = node(NODE_SIZEOF, line); n->data.unary.value = parse_unary(p); return n; }
        default:
            return parse_postfix(p);
    }
}

static ASTNode *parse_bin(Parser *p, int min_prec) {
    ASTNode *l = parse_unary(p);
    for (;;) {
        uint8_t e = BINOP[p->cur.type];
        if ((e >> 4) < min_prec) return l;
        Token t = p->cur;
        adv(p);
        ASTNode *n = node(NODE_BINARY, t.line);
        n->data.binary.op = (BinOp)(e & 15);
        n->data.binary.left = l;
        n->data.binary.right = parse_bin(p, (e >> 4) + 1);
        l = n;
    }
}

static ASTNode *parse_expression(Parser *p) {
    ASTNode *l = parse_bin(p, 1);
    if (p->cur.type == TOK_ASSIGN) {
        int line = p->cur.line;
        adv(p);
        ASTNode *n = node(NODE_ASSIGN, line);
        n->data.assign.lhs = l;
        n->data.assign.rhs = parse_expression(p);
        return n;
    }
    return l;
}

static ASTNode *parse_block(Parser *p) {
    ASTNode *b = node(NODE_BLOCK, p->cur.line);
    expect(p, TOK_LBRACE, "expected '{'");
    while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF)
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, parse_statement(p));
    expect(p, TOK_RBRACE, "expected '}'");
    return b;
}

static ASTNode *parse_statement(Parser *p) {
    Token t = p->cur;
    switch (t.type) {
        case TOK_LET: {
            adv(p);
            Type *ty = &TY_INT;
            if (p->cur.type == TOK_INT) ty = parse_type(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected var name", p->cur.line);
            ASTNode *n = node(NODE_LET, t.line);
            n->data.let.name = strdup(p->cur.text);
            n->data.let.ty = ty;
            adv(p);
            while (p->cur.type == TOK_LBRACKET) {
                adv(p);
                if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
                int sz = (int)atol(p->cur.text);
                adv(p);
                expect(p, TOK_RBRACKET, "expected ']'");
                n->data.let.ty = ty_arr(sz, n->data.let.ty);
            }
            if (p->cur.type == TOK_ASSIGN) {
                adv(p);
                n->data.let.value = parse_expression(p);
            }
            expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_PRINT: {
            adv(p);
            ASTNode *n = node(NODE_PRINT, t.line);
            n->data.print.value = parse_expression(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_IF: {
            adv(p);
            expect(p, TOK_LPAREN, "expected '('");
            ASTNode *n = node(NODE_IF, t.line);
            n->data.if_node.cond = parse_expression(p);
            expect(p, TOK_RPAREN, "expected ')'");
            n->data.if_node.then = parse_statement(p);
            if (p->cur.type == TOK_ELSE) { adv(p); n->data.if_node.else_ = parse_statement(p); }
            return n;
        }
        case TOK_WHILE: {
            adv(p);
            expect(p, TOK_LPAREN, "expected '('");
            ASTNode *n = node(NODE_WHILE, t.line);
            n->data.while_node.cond = parse_expression(p);
            expect(p, TOK_RPAREN, "expected ')'");
            n->data.while_node.body = parse_statement(p);
            return n;
        }
        case TOK_RETURN: {
            adv(p);
            ASTNode *n = node(NODE_RETURN, t.line);
            n->data.return_node.value = parse_expression(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_LBRACE: return parse_block(p);
        case TOK_FUNC:   die("func must be top-level", t.line);
        default: {
            ASTNode *e = parse_expression(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return e;
        }
    }
}

static ASTNode *parse_function(Parser *p) {
    int line = p->cur.line;
    adv(p);
    if (p->cur.type != TOK_IDENTIFIER) die("expected func name", p->cur.line);
    ASTNode *f = node(NODE_FUNCTION, line);
    f->data.function.name = strdup(p->cur.text);
    adv(p);
    expect(p, TOK_LPAREN, "expected '('");
    char **params = NULL;
    int pc = 0, pcap = 0;
    if (p->cur.type != TOK_RPAREN)
        do {
            if (p->cur.type != TOK_IDENTIFIER) die("expected param name", p->cur.line);
            PUSH(params, pc, pcap, strdup(p->cur.text));
            adv(p);
        } while (p->cur.type == TOK_COMMA && (adv(p), 1));
    expect(p, TOK_RPAREN, "expected ')'");
    f->data.function.params = params;
    f->data.function.pcount = pc;
    f->data.function.body = parse_block(p);
    return f;
}

static ASTNode *parse_program(Parser *p) {
    ASTNode *root = node(NODE_BLOCK, 0);
    while (p->cur.type != TOK_EOF)
        PUSH(root->data.block.stmts, root->data.block.count, root->data.block.cap,
             p->cur.type == TOK_FUNC ? parse_function(p) : parse_statement(p));
    return root;
}

static uint8_t code[8192];
static int clen, entry, is_pe;
static int lab_pos[256], nlab = 1;
static struct { int pos, lab; } PATCH[2048];
static int npatch;

#define EMIT(...) do {                                   \
    uint8_t _bs[] = { __VA_ARGS__ };                     \
    if (clen + (int)sizeof _bs > (int)sizeof code)       \
        die("code buffer overflow", 0);                  \
    memcpy(code + clen, _bs, sizeof _bs);                \
    clen += (int)sizeof _bs;                             \
} while (0)

static void emit_imm(long long v, int n) {
    if (clen + n > (int)sizeof code) die("code buffer overflow", 0);
    memcpy(code + clen, &v, n);
    clen += n;
}

static void mov_rax_imm(long long v) {
    if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x58);
    else if (v >= 0 && v <= 0xFFFFFFFFLL) { EMIT(0xB8); emit_imm(v, 4); }
    else { EMIT(0x48, 0xB8); emit_imm(v, 8); } 
}

static int new_label(void) { return nlab++; }
static void put_label(int lab) { lab_pos[lab] = clen; }

static void emit_rel32(int lab) { 
    if (clen + 4 > (int)sizeof code || npatch >= (int)(sizeof PATCH / sizeof *PATCH))
        die("too many jumps", 0);
    PATCH[npatch].pos = clen;
    PATCH[npatch].lab = lab;
    npatch++;
    clen += 4;
}
static void emit_jmp(int lab)  { EMIT(0xE9); emit_rel32(lab); }
static void emit_jcc(int cc, int lab) { EMIT(0x0F, cc); emit_rel32(lab); } 
static void emit_call(int lab) { EMIT(0xE8); emit_rel32(lab); }

#define PE_SECT (0x40 + 4 + 20 + 240 + 40)   

static int IAT_PATCH[16], niat;
static void emit_call_iat(int slot) {       
    EMIT(0xFF, 0x15);
    IAT_PATCH[niat++] = clen * 4 | slot;
    emit_imm(0, 4);
}

static void apply_patches(void) {
    for (int i = 0; i < npatch; i++)
        *(int32_t *)(code + PATCH[i].pos) = lab_pos[PATCH[i].lab] - (PATCH[i].pos + 4);
}

typedef struct { char *name; Type *ty; int off; } Loc;
static Loc LOCS[64];
static int nloc, cur_off;
static Loc *loc_add(const char *name, Type *ty) {
    cur_off -= ty_size(ty);
    LOCS[nloc] = (Loc){ strdup(name), ty, cur_off };
    return &LOCS[nloc++];
}
static Loc *loc_find(const char *name) {
    for (int i = nloc - 1; i >= 0; i--)
        if (!strcmp(LOCS[i].name, name)) return &LOCS[i];
    return NULL;
}

static struct { char *name; int lab, params; } FNS[64];
static int nfn;
static int fn_find(const char *name) {
    for (int i = 0; i < nfn; i++)
        if (!strcmp(FNS[i].name, name)) return i;
    return -1;
}

static int setcc_of(BinOp op) {
    return op < OP_LT ? 0x90 | op : 0x9C | (-(op - OP_LT) & 3);
}

static const uint8_t PRINT_INT_CODE[] = {
    0x55,                    
    0x48,0x89,0xE5,            
    0x48,0x83,0xEC,0x20,       
    0x48,0x89,0xF8,            
    0x6A,0x0A,0x59,            
    0x48,0x8D,0x75,0xFF,       
    0x48,0x31,0xD2,            
    0x48,0xF7,0xF1,            
    0x80,0xC2,0x30,             
    0x48,0xFF,0xCE,            
    0x88,0x16,                  
    0x48,0x85,0xC0,            
    0x75,0xED,                  
    0x48,0x8D,0x55,0xFF,       
    0x48,0x29,0xF2,             
    0x6A,0x01,0x58,             
    0x89,0xC7,                  
    0x0F,0x05,                 
    0xC9,0xC3,                 
};

static void emit_print_pe(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x50);
    EMIT(0x48,0x89,0xF8);
    EMIT(0x6A,0x0A,0x59);
    EMIT(0x48,0x8D,0x75,0xFF);
    int loop = new_label();
    put_label(loop);
    EMIT(0x48,0x31,0xD2);
    EMIT(0x48,0xF7,0xF1);
    EMIT(0x80,0xC2,0x30);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0x88,0x16);
    EMIT(0x48,0x85,0xC0);
    emit_jcc(0x85, loop);
    EMIT(0x6A,0xF5,0x59);
    emit_call_iat(0);
    EMIT(0x48,0x89,0xC1);
    EMIT(0x48,0x89,0xF2);
    EMIT(0x4C,0x8D,0x45,0xFF);
    EMIT(0x49,0x29,0xF0);
    EMIT(0x4C,0x8D,0x4C,0x24,0x28);
    EMIT(0x48,0xC7,0x44,0x24,0x20); emit_imm(0,4);
    emit_call_iat(1);
    EMIT(0xC9,0xC3);
}

static void gen_expr(ASTNode*);
static void gen_stmt(ASTNode*);

static void mov_rax_imm(long long v);

static int ty_size_of_expr(ASTNode *n) {
    if (n->type == NODE_VARIABLE) {
        Loc *l = loc_find(n->data.variable.name);
        return l ? ty_size(l->ty) : 8;
    }
    return 8;
}

static void gen_addr(ASTNode *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            Loc *l = loc_find(n->data.variable.name);
            if (!l) die("undefined variable", n->line);
            EMIT(0x48, 0x8D, 0x45, (uint8_t)l->off);
            break;
        }
        case NODE_DEREF:
            gen_expr(n->data.unary.value);
            break;
        case NODE_INDEX:
            gen_addr(n->data.index.base);
            EMIT(0x50);
            gen_expr(n->data.index.index);
            EMIT(0x48, 0xC1, 0xE0, 0x03);   
            EMIT(0x5B, 0x48, 0x01, 0xD8);   
            break;
        default:
            die("not addressable", n->line);
    }
}

static void gen_expr(ASTNode *n) {
    switch (n->type) {
        case NODE_NUMBER:
            EMIT(0x48, 0xB8); 
            emit_imm(n->data.number.value, 8);
            break;
        case NODE_VARIABLE: {
            Loc *l = loc_find(n->data.variable.name);
            if (!l) die("undefined variable", n->line);
            if (l->ty->kind == 2) EMIT(0x48, 0x8D, 0x45, (uint8_t)l->off); 
            else EMIT(0x48, 0x8B, 0x45, (uint8_t)l->off);                  
            break;
        }
        case NODE_ADDR:
            gen_addr(n->data.unary.value);
            break;
        case NODE_DEREF:
            gen_expr(n->data.unary.value);
            EMIT(0x48, 0x8B, 0x00);  
            break;
        case NODE_INDEX:
            gen_addr(n);
            EMIT(0x48, 0x8B, 0x00);  
            break;
        case NODE_ASSIGN:
            gen_addr(n->data.assign.lhs);
            EMIT(0x50);
            gen_expr(n->data.assign.rhs);
            EMIT(0x5B, 0x48, 0x89, 0x03);  
            break;
        case NODE_SIZEOF:
            mov_rax_imm(ty_size_of_expr(n->data.unary.value));
            break;
        case NODE_BINARY: {
            BinOp op = n->data.binary.op;
            if (op >= OP_EQ) { 
                gen_expr(n->data.binary.right); EMIT(0x50);       
                gen_expr(n->data.binary.left);  EMIT(0x5B);   
                EMIT(0x48, 0x39, 0xD8);                       
                EMIT(0x0F, setcc_of(op), 0xC0);                 
                EMIT(0x48, 0x0F, 0xB6, 0xC0);                     
                break;
            }
            gen_expr(n->data.binary.left);  EMIT(0x50);
            gen_expr(n->data.binary.right); EMIT(0x5B);
            switch (op) {
                case OP_ADD: EMIT(0x48, 0x01, 0xD8); break;                            
                case OP_SUB: EMIT(0x48, 0x93, 0x48, 0x29, 0xD8); break;                 
                case OP_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC3); break;                        
                case OP_DIV: EMIT(0x48, 0x93, 0x48, 0x31, 0xD2, 0x48, 0xF7, 0xF3); break; 
                default: break;
            }
            break;
        }
        case NODE_CALL: {
            if (n->data.call.acount > 1) die("at most 1 argument", n->line);
            int f = fn_find(n->data.call.name);
            if (f < 0) { fprintf(stderr, "error: unknown func %s\n", n->data.call.name); exit(1); }
            for (int i = 0; i < n->data.call.acount; i++) {
                gen_expr(n->data.call.args[i]);
                EMIT(0x48, 0x89, 0xC7); 
            }
            emit_call(FNS[f].lab);
            break;
        }
        default:
            die("unsupported expression", n->line);
    }
}

static void gen_stmt(ASTNode *n) {
    switch (n->type) {
        case NODE_LET: {
            if (n->data.let.value) gen_expr(n->data.let.value);
            Loc *l = loc_add(n->data.let.name, n->data.let.ty);
            if (n->data.let.ty->kind == 2) {
                EMIT(0x48, 0x8D, 0x7D, (uint8_t)l->off);   
                if (n->data.let.value) EMIT(0x48, 0x89, 0x07);   
                else {
                    EMIT(0x48, 0x31, 0xC0);       
                    EMIT(0xB9); emit_imm(n->data.let.ty->len, 4);  
                    EMIT(0xF3, 0x48, 0xAB);            
                }
            } else {
                if (!n->data.let.value) die("missing initializer", n->line);
                EMIT(0x48, 0x89, 0x45, (uint8_t)l->off);
            }
            break;
        }
        case NODE_PRINT:
            gen_expr(n->data.print.value);
            EMIT(0x48, 0x89, 0xC7);         
            EMIT(0xE8);                       
            emit_imm(-(clen + 4), 4);
            break;
        case NODE_BLOCK:
            for (int i = 0; i < n->data.block.count; i++) gen_stmt(n->data.block.stmts[i]);
            break;
        case NODE_IF: {
            gen_expr(n->data.if_node.cond);
            EMIT(0x48, 0x85, 0xC0);  
            int lab_else = new_label(), lab_end = new_label();
            emit_jcc(0x84, lab_else);        
            gen_stmt(n->data.if_node.then);
            emit_jmp(lab_end);
            put_label(lab_else);
            if (n->data.if_node.else_) gen_stmt(n->data.if_node.else_);
            put_label(lab_end);
            break;
        }
        case NODE_WHILE: {
            int lab_start = new_label(), lab_end = new_label();
            put_label(lab_start);
            gen_expr(n->data.while_node.cond);
            EMIT(0x48, 0x85, 0xC0);     
            emit_jcc(0x84, lab_end);         
            gen_stmt(n->data.while_node.body);
            emit_jmp(lab_start);
            put_label(lab_end);
            break;
        }
        case NODE_RETURN:
            gen_expr(n->data.return_node.value);
            EMIT(0xC9, 0xC3);                  
            break;
        default:
            gen_expr(n); 
            break;
    }
}

#define PROLOGUE EMIT(0x55, 0x48,0x89,0xE5, 0x48,0x83,0xEC,0x40) 

static void generate_code(ASTNode *root) {
    clen = 0;
    if (is_pe) emit_print_pe();
    else { memcpy(code, PRINT_INT_CODE, sizeof PRINT_INT_CODE); clen = sizeof PRINT_INT_CODE; }

    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        FNS[nfn] = (typeof(FNS[0])){ strdup(f->data.function.name), new_label(), f->data.function.pcount };
        nfn++;
    }
    for (int i = 0; i < root->data.block.count; i++) { 
        ASTNode *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        put_label(FNS[fn_find(f->data.function.name)].lab);
        PROLOGUE;
        nloc = 0; cur_off = 0;
        if (f->data.function.pcount > 0) { 
            EMIT(0x48, 0x89, 0xF8); 
            EMIT(0x48, 0x89, 0x45, (uint8_t)loc_add(f->data.function.params[0], &TY_INT)->off);
        }
        gen_stmt(f->data.function.body);
        EMIT(0xC9, 0xC3); 
    }

    put_label(new_label());
    entry = clen;
    PROLOGUE;
    nloc = 0; cur_off = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type != NODE_FUNCTION) gen_stmt(n);
    }
    if (is_pe) {
        EMIT(0x31, 0xC9);    
        emit_call_iat(2);
        apply_patches();
        uint32_t imp_rva = PE_SECT + ((clen + 15) & ~15);
        for (int i = 0; i < niat; i++) {
            int pos = IAT_PATCH[i] >> 2, slot = IAT_PATCH[i] & 3;
            *(int32_t *)(code + pos) = imp_rva + 72 + (slot << 3) - (PE_SECT + pos + 4);
        }
    } else {
        mov_rax_imm(60);    
        EMIT(0x31, 0xFF);    
        EMIT(0x0F, 0x05);   
        apply_patches();
    }
}

static void write_elf(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint64_t hdr_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr); 
    const uint64_t base = 0x400000;

    Elf64_Ehdr ehdr = {
        .e_ident = { 0x7f, 'E', 'L', 'F', 2, 1, 1 }, 
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = base + hdr_size + entry,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
    };
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_X,
        .p_offset = 0,
        .p_vaddr = base,
        .p_paddr = base,
        .p_filesz = hdr_size + clen,
        .p_memsz = hdr_size + clen,
        .p_align = 0x1000,
    };

    write(fd, &ehdr, sizeof ehdr);
    write(fd, &phdr, sizeof phdr);
    write(fd, code, clen);
    close(fd);
}

static void put(uint8_t *p, uint64_t v, int n) { memcpy(p, &v, n); }

static void write_pe(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint32_t body = (clen + 15) & ~15;
    const uint32_t imp_rva = PE_SECT + body;
    const uint32_t vsize = body + 176;
    uint8_t h[PE_SECT] = {0}, imp[176] = {0}, zero[16] = {0};

    h[0] = 'M'; h[1] = 'Z';
    put(h + 0x3C, 0x40, 4);
    memcpy(h + 0x40, "PE\0\0", 4);
    put(h + 0x44, 0x8664, 2);
    put(h + 0x46, 1, 2);
    put(h + 0x54, 0xF0, 2);
    put(h + 0x56, 0x22, 2);
    put(h + 0x58, 0x20B, 2);
    put(h + 0x5C, clen, 4);
    put(h + 0x68, PE_SECT + entry, 4);
    put(h + 0x6C, PE_SECT, 4);
    put(h + 0x70, 0x400000, 8);
    put(h + 0x78, 0x10, 4);
    put(h + 0x7C, 0x10, 4);
    put(h + 0x88, 6, 2);
    put(h + 0x90, PE_SECT + vsize, 4);
    put(h + 0x94, PE_SECT, 4);
    put(h + 0x9C, 3, 2);
    put(h + 0xA0, 0x100000, 8);
    put(h + 0xA8, 0x1000, 8);
    put(h + 0xB0, 0x100000, 8);
    put(h + 0xB8, 0x1000, 8);
    put(h + 0xC4, 16, 4);
    put(h + 0xD0, imp_rva, 4);
    put(h + 0xD4, 40, 4);
    put(h + 0x150, vsize, 4);
    put(h + 0x154, PE_SECT, 4);
    put(h + 0x158, vsize, 4);
    put(h + 0x15C, PE_SECT, 4);
    put(h + 0x16C, 0x60000020, 4);

    put(imp + 12, imp_rva + 104, 4);
    put(imp + 16, imp_rva + 72, 4);
    memcpy(imp + 104, "kernel32.dll", 13);
    const char *FN[3] = { "GetStdHandle", "WriteFile", "ExitProcess" };
    for (int i = 0, off = 120; i < 3; i++) {
        put(imp + 40 + i * 8, imp_rva + off, 4);
        put(imp + 72 + i * 8, imp_rva + off, 4);
        memcpy(imp + off + 2, FN[i], strlen(FN[i]));
        off += (int)(strlen(FN[i]) + 4) & ~1;
    }

    write(fd, h, PE_SECT);
    write(fd, code, clen);
    if (body > (uint32_t)clen) write(fd, zero, body - clen);
    write(fd, imp, 176);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <source-file> [output-file]\n", argv[0]); return 1; }
    const char *out = argc >= 3 ? argv[2] : "a.out";
    size_t ol = strlen(out);
    is_pe = ol >= 4 && !memcmp(out + ol - 4, ".exe", 4);

    FILE *sf = fopen(argv[1], "rb");
    if (!sf) { perror(argv[1]); return 1; }
    fseek(sf, 0, SEEK_END);
    long size = ftell(sf);
    rewind(sf);
    char *src = malloc(size + 1);
    if (!src || fread(src, 1, size, sf) != (size_t)size) { fprintf(stderr, "Cannot read %s\n", argv[1]); return 1; }
    src[size] = 0;
    fclose(sf);

    printf("Compiling %s...\n", argv[1]);

    Lexer lx = { src, 0, 1 };
    Token *tokens = NULL;
    int tcnt = 0, tcap = 0;
    Token tk;
    do {
        tk = next_token(&lx);
        PUSH(tokens, tcnt, tcap, tk);
    } while (tk.type != TOK_EOF && tk.type != TOK_ERROR);
    if (tk.type == TOK_ERROR) { fprintf(stderr, "Lex error\n"); return 1; }

    Parser p = { tokens, tcnt, 0 };
    adv(&p);
    generate_code(parse_program(&p));
    if (is_pe) write_pe(out); else write_elf(out);

    printf("Generated %s (%s x86-64)\n", out, is_pe ? "PE32+" : "ELF");
    return 0;
}

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
#define PF_W 2
#define PF_X 1
#else
#include <elf.h>
#define O_BINARY 0
#endif

static void die(const char *msg, int line) {
    fprintf(stderr, "error (line %d): %s\n", line, msg);
    exit(1);
}

#define STR_CAP (1 << 20)
static char STR[STR_CAP];
static int stroff;
static char *str_put(const char *s, int len) {
    if (stroff + len + 1 > STR_CAP) die("source too large", 0);
    char *p = STR + stroff;
    stroff += len + 1;
    memcpy(p, s, len);
    p[len] = 0;
    return p;
}

static unsigned sfnv(const char *s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}
#define HSZ 128   

#define PUSH(arr, n, cap, item) do {                                     \
    if ((n) >= (cap)) {                                                  \
        (cap) = (cap) ? (cap) * 2 : 4;                                   \
        (arr) = realloc((arr), (cap) * sizeof *(arr));                   \
    }                                                                    \
    (arr)[(n)++] = (item);                                               \
} while (0)

typedef enum {
    TOK_LET, TOK_PRINT, TOK_IF, TOK_ELSE, TOK_WHILE, TOK_RETURN, TOK_FUNC,
    TOK_SIZEOF, TOK_INT, TOK_CHAR, TOK_CONST, TOK_BREAK, TOK_CONTINUE, TOK_EXTERN,
    TOK_STR,
    TOK_IDENTIFIER, TOK_NUMBER,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH,
    TOK_AMP, TOK_PIPE, TOK_CARET, TOK_TILDE, TOK_SHL, TOK_SHR,
    TOK_LBRACKET, TOK_RBRACKET,
    TOK_ASSIGN, TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_SEMICOLON, TOK_COMMA,
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_PERCENT, TOK_ANDAND, TOK_OROR,
    TOK_PLUS_EQ, TOK_MINUS_EQ, TOK_STAR_EQ, TOK_SLASH_EQ, TOK_PERCENT_EQ, TOK_NOT,
    TOK_AT,
    TOK_EOF, TOK_ERROR
} TokenType;

typedef struct { TokenType type; char *text; int line; } Token;
typedef struct { const char *src; int pos, line; } Lexer;

static Token tok(TokenType t, const char *s, int len, int line) {
    Token tk = { t, str_put(s, len), line };
    return tk;
}

static const char *KWD[] = { "let", "print", "if", "else", "while", "return", "func", "sizeof", "int", "char", "const", "break", "continue", "extern" };

static const uint64_t PUNCT_BIT[2] = {
    (1ULL << 33) | (1ULL << 37) | (1ULL << 38) | (1ULL << 40) | (1ULL << 41) | (1ULL << 42) | (1ULL << 43) |
    (1ULL << 44) | (1ULL << 45) | (1ULL << 47) | (1ULL << 59) |
    (1ULL << 60) | (1ULL << 61) | (1ULL << 62),
    (1ULL << 27) | (1ULL << 29) | (1ULL << 30) | (1ULL << 59) | (1ULL << 60) | (1ULL << 61) | (1ULL << 62) |
    (1ULL << 0),
};

static const uint64_t PAIR_BIT[2] = {
    (1ULL << 33) | (1ULL << 37) | (1ULL << 42) | (1ULL << 43) | (1ULL << 45) |
    (1ULL << 47) | (1ULL << 60) | (1ULL << 61) | (1ULL << 62), 0,
};

static const TokenType CHAR_TOK[128] = {
    ['+'] = TOK_PLUS, ['-'] = TOK_MINUS, ['*'] = TOK_STAR, ['/'] = TOK_SLASH,
    ['&'] = TOK_AMP, ['%'] = TOK_PERCENT,
    ['['] = TOK_LBRACKET, [']'] = TOK_RBRACKET,
    [';'] = TOK_SEMICOLON, [','] = TOK_COMMA,
    ['('] = TOK_LPAREN, [')'] = TOK_RPAREN, ['{'] = TOK_LBRACE, ['}'] = TOK_RBRACE,
    ['='] = TOK_ASSIGN, ['!'] = TOK_NOT, ['<'] = TOK_LT, ['>'] = TOK_GT,
    ['|'] = TOK_PIPE, ['^'] = TOK_CARET, ['~'] = TOK_TILDE, ['@'] = TOK_AT,
};

static const TokenType PAIR2_TOK[128] = {
    ['='] = TOK_EQ, ['!'] = TOK_NE, ['<'] = TOK_LE, ['>'] = TOK_GE,
    ['+'] = TOK_PLUS_EQ, ['-'] = TOK_MINUS_EQ, ['*'] = TOK_STAR_EQ,
    ['/'] = TOK_SLASH_EQ, ['%'] = TOK_PERCENT_EQ,
};

static Token next_token(Lexer *lx) {
    for (;;) {
        while (isspace(lx->src[lx->pos])) {
            if (lx->src[lx->pos] == '\n') lx->line++;
            lx->pos++;
        }
        if (lx->src[lx->pos] == '/' && lx->src[lx->pos + 1] == '/') {
            lx->pos += 2;
            while (lx->src[lx->pos] && lx->src[lx->pos] != '\n') lx->pos++;
            continue;
        }
        break;
    }
    int s = lx->pos, line = lx->line;
    char c = lx->src[s];
    if (!c) return tok(TOK_EOF, "", 0, line);
    if (isalpha(c) || c == '_') {
        while (isalnum(lx->src[lx->pos]) || lx->src[lx->pos] == '_') lx->pos++;
        int len = lx->pos - s;
        for (int i = 0; i < 14; i++)
            if (len == (int)strlen(KWD[i]) && !memcmp(&lx->src[s], KWD[i], len))
                return tok(TOK_LET + i, &lx->src[s], len, line);
        return tok(TOK_IDENTIFIER, &lx->src[s], len, line);
    }
    if (isdigit(c)) {
        if (c == '0' && (lx->src[s + 1] == 'x' || lx->src[s + 1] == 'X')) {
            lx->pos = s + 2;
            while (isxdigit(lx->src[lx->pos])) lx->pos++;
        } else
            while (isdigit(lx->src[lx->pos])) lx->pos++;
        return tok(TOK_NUMBER, &lx->src[s], lx->pos - s, line);
    }
    if (c == '"') {
        lx->pos++;
        while (lx->src[lx->pos] && lx->src[lx->pos] != '"')
            lx->pos += lx->src[lx->pos] == '\\' && lx->src[lx->pos + 1] ? 2 : 1;
        if (lx->src[lx->pos] != '"') return tok(TOK_ERROR, &lx->src[s], 1, line);
        lx->pos++;
        return tok(TOK_STR, &lx->src[s], lx->pos - s, line);
    }
    if (c == '\'') {
        lx->pos = s + 1;
        int ch = (unsigned char)lx->src[lx->pos];
        if (ch == '\\') {
            lx->pos++;
            ch = lx->src[lx->pos];
            ch = ch == 'n' ? '\n' : ch == 't' ? '\t' : ch == '0' ? 0 : ch;
        }
        if (!lx->src[lx->pos] || lx->src[lx->pos + 1] != '\'')
            return tok(TOK_ERROR, &lx->src[s], 1, line);
        lx->pos += 2;
        char buf[16], rev[16];
        int n = 0;
        unsigned u = (unsigned)ch;
        do { buf[n++] = (char)('0' + u % 10); u /= 10; } while (u);
        for (int i = 0; i < n; i++) rev[i] = buf[n - 1 - i];
        Token tk = { TOK_NUMBER, str_put(rev, n), line };
        return tk;
    }
    if (c == '&' && lx->src[s + 1] == '&') {
        lx->pos = s + 2;
        return tok(TOK_ANDAND, &lx->src[s], 2, line);
    }
    if (c == '|' && lx->src[s + 1] == '|') {
        lx->pos = s + 2;
        return tok(TOK_OROR, &lx->src[s], 2, line);
    }
    if ((c == '<' || c == '>') && lx->src[s + 1] == c) {
        lx->pos = s + 2;
        return tok(c == '<' ? TOK_SHL : TOK_SHR, &lx->src[s], 2, line);
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
    NODE_ADDR, NODE_DEREF, NODE_INDEX, NODE_ASSIGN, NODE_SIZEOF, NODE_STR, NODE_NOT,
    NODE_BNOT, NODE_BREAK, NODE_CONTINUE, NODE_EXTERN_FUNC, NODE_EXTERN_GLOB
} NodeType;
typedef enum { OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_EQ, OP_NE, OP_LT, OP_GT, OP_LE, OP_GE, OP_MOD, OP_AND, OP_OR,
               OP_BOR, OP_BAND, OP_BXOR, OP_SHL, OP_SHR } BinOp;

typedef struct Type { uint8_t kind; int len; uint8_t sz; struct Type *base; } Type;

static Type TY_INT = { 0, 0, 8, NULL }, TY_CHAR = { 0, 0, 1, NULL };
static Type *ty_ptr(Type *b) {
    static Type t[512]; static int n;
    if (n >= (int)(sizeof t / sizeof *t)) die("too many types", 0);
    t[n] = (Type){ 1, 0, 8, b };
    return &t[n++];
}
static Type *ty_arr(int n, Type *b) {
    static Type t[512]; static int c;
    if (c >= (int)(sizeof t / sizeof *t)) die("too many types", 0);
    t[c] = (Type){ 2, n, 8, b };
    return &t[c++];
}
static int ty_size(Type *t) { return t->kind == 2 ? t->len * ty_size(t->base) : t->sz; }
static int is_char(Type *t) { return t->kind == 0 && t->sz == 1; }

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
        struct { char *name; char **params; Type **ptypes; int pcount; struct ASTNode *body; } function;
        struct { char *name; struct ASTNode **args; int acount; } call;
        struct { struct ASTNode *value; } unary;
        struct { struct ASTNode *base, *index; } index;
        struct { struct ASTNode *lhs, *rhs; int cop; } assign;
        struct { char *name; int pcount; } extfn;
        struct { char *name; } extgl;
        struct { int off, len; } str;
    } data;
} ASTNode;

#define NODE_CAP (1 << 18)
static ASTNode NODE_ARENA[NODE_CAP];
static int nodeoff;
static ASTNode *node(NodeType t, int line) {
    if (nodeoff >= NODE_CAP) die("too many AST nodes", 0);
    ASTNode *n = &NODE_ARENA[nodeoff++];
    memset(n, 0, sizeof *n);
    n->type = t; n->line = line;
    return n;
}

static ASTNode *mkbin(BinOp op, ASTNode *l, ASTNode *r, int line) {
    if (l->type == NODE_NUMBER && r->type == NODE_NUMBER) {
        long a = l->data.number.value, b = r->data.number.value, v = 0;
        switch (op) {
            case OP_ADD: v = a + b; break;
            case OP_SUB: v = a - b; break;
            case OP_MUL: v = a * b; break;
            case OP_DIV: if (!b) die("division by zero", line); v = a / b; break;
            case OP_MOD: if (!b) die("modulo by zero", line); v = a % b; break;
            case OP_EQ:  v = a == b; break;
            case OP_NE:  v = a != b; break;
            case OP_LT:  v = a < b; break;
            case OP_GT:  v = a > b; break;
            case OP_LE:  v = a <= b; break;
            case OP_GE:  v = a >= b; break;
            case OP_AND: v = a && b; break;
            case OP_OR:  v = a || b; break;
            case OP_BOR:  v = a | b; break;
            case OP_BAND: v = a & b; break;
            case OP_BXOR: v = a ^ b; break;
            case OP_SHL:  v = a << (b & 63); break;
            case OP_SHR:  v = a >> (b & 63); break;
        }
        ASTNode *n = node(NODE_NUMBER, line);
        n->data.number.value = v;
        return n;
    }
    ASTNode *n = node(NODE_BINARY, line);
    n->data.binary.op = op;
    n->data.binary.left = l;
    n->data.binary.right = r;
    return n;
}

static struct { char *name; long value; } CONSTS[256];
static int nconst;
static int const_find(const char *name) {
    for (int i = 0; i < nconst; i++)
        if (!strcmp(CONSTS[i].name, name)) return i;
    return -1;
}

typedef struct { Token *tokens; int count, pos; Token cur; } Parser;

static void adv(Parser *p) { p->cur = p->pos < p->count ? p->tokens[p->pos++] : (Token){ TOK_EOF, NULL, 0 }; }

static void expect(Parser *p, TokenType t, const char *what) {
    if (p->cur.type != t) die(what, p->cur.line);
    adv(p);
}

static const uint16_t BINOP[TOK_ERROR + 1] = {
    [TOK_EQ] = OP_EQ | 6 << 5,  [TOK_NE] = OP_NE | 6 << 5,
    [TOK_LT] = OP_LT | 6 << 5,  [TOK_GT] = OP_GT | 6 << 5,
    [TOK_LE] = OP_LE | 6 << 5,  [TOK_GE] = OP_GE | 6 << 5,
    [TOK_PLUS] = OP_ADD | 9 << 5, [TOK_MINUS] = OP_SUB | 9 << 5,
    [TOK_STAR] = OP_MUL | 10 << 5, [TOK_SLASH] = OP_DIV | 10 << 5,
    [TOK_PERCENT] = OP_MOD | 10 << 5,
    [TOK_ANDAND] = OP_AND | 2 << 5,
    [TOK_OROR] = OP_OR | 1 << 5,
    [TOK_PIPE] = OP_BOR | 3 << 5,
    [TOK_CARET] = OP_BXOR | 4 << 5,
    [TOK_AMP] = OP_BAND | 5 << 5,
    [TOK_SHL] = OP_SHL | 8 << 5, [TOK_SHR] = OP_SHR | 8 << 5,
};

static uint8_t LIT[16384];
static int nlit;

static ASTNode *parse_expression(Parser*);
static ASTNode *parse_statement(Parser*);
static ASTNode *parse_block(Parser*);

static Type *parse_type(Parser *p) {
    if (p->cur.type != TOK_INT && p->cur.type != TOK_CHAR) die("expected type", p->cur.line);
    Type *t = p->cur.type == TOK_CHAR ? &TY_CHAR : &TY_INT;
    adv(p);
    for (;;) {
        if (p->cur.type == TOK_STAR) { adv(p); t = ty_ptr(t); }
        else if (p->cur.type == TOK_LBRACKET) {
            adv(p);
            if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
            int n = (int)strtoll(p->cur.text, 0, 0);
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
        n->data.number.value = strtoll(t.text, 0, 0);
        return n;
    }
    if (t.type == TOK_IDENTIFIER) {
        for (int i = 0; i < nconst; i++)
            if (!strcmp(CONSTS[i].name, t.text)) {
                adv(p);
                ASTNode *n = node(NODE_NUMBER, t.line);
                n->data.number.value = CONSTS[i].value;
                return n;
            }
        adv(p);
        if (p->cur.type != TOK_LPAREN) {
            ASTNode *n = node(NODE_VARIABLE, t.line);
            n->data.variable.name = t.text;
            return n;
        }
        adv(p);
        ASTNode *n = node(NODE_CALL, t.line);
        n->data.call.name = t.text;
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
    if (t.type == TOK_STR) {
        adv(p);
        ASTNode *n = node(NODE_STR, t.line);
        n->data.str.off = nlit;
        for (int i = 1; t.text[i] != '"'; i++) {
            char ch = t.text[i];
            if (ch == '\\') {
                ch = t.text[++i];
                ch = ch == 'n' ? '\n' : ch == 't' ? '\t' : ch;
            }
            if (nlit >= (int)sizeof LIT) die("string pool overflow", t.line);
            LIT[nlit++] = ch;
        }
        if (nlit >= (int)sizeof LIT) die("string pool overflow", t.line);
        LIT[nlit++] = 0;
        n->data.str.len = nlit - n->data.str.off - 1;
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
            return mkbin(OP_SUB, zero, parse_unary(p), line);
        }
        case TOK_AMP:
            adv(p);
            { ASTNode *n = node(NODE_ADDR, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_STAR:
            adv(p);
            { ASTNode *n = node(NODE_DEREF, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_NOT:
            adv(p);
            { ASTNode *n = node(NODE_NOT, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_TILDE:
            adv(p);
            { ASTNode *n = node(NODE_BNOT, line); n->data.unary.value = parse_unary(p); return n; }
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
        uint16_t e = BINOP[p->cur.type];
        if ((e >> 5) < min_prec) return l;
        Token t = p->cur;
        adv(p);
        l = mkbin((BinOp)(e & 31), l, parse_bin(p, (e >> 5) + 1), t.line);
    }
}

static ASTNode *parse_expression(Parser *p) {
    ASTNode *l = parse_bin(p, 1);
    int cop = 0;
    switch (p->cur.type) {
        case TOK_ASSIGN:     cop = 0; break;
        case TOK_PLUS_EQ:    cop = OP_ADD + 1; break;
        case TOK_MINUS_EQ:   cop = OP_SUB + 1; break;
        case TOK_STAR_EQ:    cop = OP_MUL + 1; break;
        case TOK_SLASH_EQ:   cop = OP_DIV + 1; break;
        case TOK_PERCENT_EQ: cop = OP_MOD + 1; break;
        default: return l;
    }
    int line = p->cur.line;
    adv(p);
    ASTNode *n = node(NODE_ASSIGN, line);
    n->data.assign.lhs = l;
    n->data.assign.cop = cop;
    n->data.assign.rhs = parse_expression(p);
    return n;
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
        case TOK_CONST: {
            adv(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected const name", p->cur.line);
            if (nconst >= (int)(sizeof CONSTS / sizeof *CONSTS)) die("too many consts", p->cur.line);
            CONSTS[nconst].name = p->cur.text;
            adv(p);
            expect(p, TOK_ASSIGN, "expected '=' in const");
            long v = 0;
            int neg = p->cur.type == TOK_MINUS;
            if (neg) adv(p);
            if (p->cur.type != TOK_NUMBER) die("const must be a number", p->cur.line);
            v = strtoll(p->cur.text, 0, 0);
            adv(p);
            CONSTS[nconst].value = neg ? -v : v;
            nconst++;
            expect(p, TOK_SEMICOLON, "expected ';'");
            return node(NODE_BLOCK, t.line);
        }
        case TOK_LET: {
            adv(p);
            Type *ty = &TY_INT;
            if (p->cur.type == TOK_INT || p->cur.type == TOK_CHAR) ty = parse_type(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected var name", p->cur.line);
            ASTNode *n = node(NODE_LET, t.line);
            n->data.let.name = p->cur.text;
            n->data.let.ty = ty;
            adv(p);
            while (p->cur.type == TOK_LBRACKET) {
                adv(p);
                if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
                int sz = (int)strtoll(p->cur.text, 0, 0);
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
        case TOK_BREAK:
            adv(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return node(NODE_BREAK, t.line);
        case TOK_CONTINUE:
            adv(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return node(NODE_CONTINUE, t.line);
        case TOK_RETURN: {
            adv(p);
            ASTNode *n = node(NODE_RETURN, t.line);
            n->data.return_node.value = parse_expression(p);
            expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_EXTERN: {
            adv(p);
            if (p->cur.type == TOK_FUNC) {
                adv(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected extern func name", p->cur.line);
                ASTNode *n = node(NODE_EXTERN_FUNC, t.line);
                n->data.extfn.name = p->cur.text;
                adv(p);
                expect(p, TOK_LPAREN, "expected '('");
                int pc = 0;
                if (p->cur.type != TOK_RPAREN)
                    do {
                        if (p->cur.type != TOK_IDENTIFIER) die("expected param name", p->cur.line);
                        pc++;
                        adv(p);
                    } while (p->cur.type == TOK_COMMA && (adv(p), 1));
                expect(p, TOK_RPAREN, "expected ')'");
                n->data.extfn.pcount = pc;
                expect(p, TOK_SEMICOLON, "expected ';'");
                return n;
            }
            if (p->cur.type == TOK_LET) {
                adv(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected extern let name", p->cur.line);
                ASTNode *n = node(NODE_EXTERN_GLOB, t.line);
                n->data.extgl.name = p->cur.text;
                adv(p);
                expect(p, TOK_SEMICOLON, "expected ';'");
                return n;
            }
            die("expected 'func' or 'let' after extern", t.line);
            return NULL;
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
    f->data.function.name = p->cur.text;
    adv(p);
    expect(p, TOK_LPAREN, "expected '('");
    char **params = NULL;
    int pc = 0, pcap = 0;
    if (p->cur.type != TOK_RPAREN)
        do {
            if (p->cur.type != TOK_IDENTIFIER) die("expected param name", p->cur.line);
            PUSH(params, pc, pcap, p->cur.text);
            adv(p);
        } while (p->cur.type == TOK_COMMA && (adv(p), 1));
    expect(p, TOK_RPAREN, "expected ')'");
    f->data.function.params = params;
    f->data.function.pcount = pc;
    f->data.function.body = parse_block(p);
    return f;
}

enum { FMT_ELF, FMT_BIN, FMT_PE };
static int fmt = FMT_ELF;
static long long load_base = 0x400000;
static char *entry_name;
static int freestanding;
static int raw_mode;
static int boot_mode;
static int bin_fmt;
static int printlab;

static void parse_directive(Parser *p) {
    int line = p->cur.line;
    adv(p);
    if (p->cur.type != TOK_IDENTIFIER) die("directive name expected", line);
    char *d = p->cur.text;
    adv(p);
    if (!strcmp(d, "base")) {
        if (p->cur.type != TOK_NUMBER) die("@base needs a number", line);
        load_base = strtoll(p->cur.text, 0, 0);
        adv(p);
    } else if (!strcmp(d, "entry")) {
        if (p->cur.type != TOK_IDENTIFIER) die("@entry needs a symbol", line);
        entry_name = p->cur.text;
        adv(p);
    } else if (!strcmp(d, "bin")) fmt = FMT_BIN;
    else if (!strcmp(d, "elf")) fmt = FMT_ELF;
    else if (!strcmp(d, "pe"))  fmt = FMT_PE;
    else if (!strcmp(d, "nort")) freestanding = 1;
    else if (!strcmp(d, "raw")) raw_mode = 1;
    else if (!strcmp(d, "boot")) boot_mode = 1;
    else die("unknown directive", line);
    expect(p, TOK_SEMICOLON, "expected ';' after directive");
}

static ASTNode *parse_program(Parser *p) {
    ASTNode *root = node(NODE_BLOCK, 0);
    while (p->cur.type != TOK_EOF) {
        if (p->cur.type == TOK_AT) { parse_directive(p); continue; }
        PUSH(root->data.block.stmts, root->data.block.count, root->data.block.cap,
             p->cur.type == TOK_FUNC ? parse_function(p) : parse_statement(p));
    }
    return root;
}

static uint8_t code[262144];
static int clen, entry, is_pe;
static int lab_pos[8192], nlab = 1;
static struct { int pos, lab, g; } PATCH[8192];   
static int npatch, litlab, pcb;

enum {
    RI_MOVB, RI_MOVW, RI_MOVL, RI_MOVQ, RI_XORW, RI_XORL, RI_MOVSREG,
    RI_ORB, RI_ORL, RI_INTN, RI_INAL, RI_OUTAL, RI_CRRD, RI_CRWR,
    RI_ST32, RI_CLD, RI_RDMSR, RI_WRMSR, RI_REPMOVSQ, RI_JMPRAX,
    RI_LABEL, RI_LJMP16, RI_LJMP32, RI_JC, RI_JMP, RI_LGDTAT, RI_GDTDESC
};
static const char *RINAME[] = {
    "set8", "set16", "set32", "set64", "xor16", "xor32", "setseg",
    "or8", "or32", "int_n", "in_al", "out_al", "readcr", "writecr",
    "setmem32", "cld", "rdmsr", "wrmsr", "rep_movsq", "jmp_rax",
    "label", "ljmp16", "ljmp32", "jc", "jmp", "lgdt_at", "gdt_desc16"
};
static const int RINARG[] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2,
    2, 0, 0, 0, 0, 0, 1, 2, 2, 1, 1, 1, 2
};
static int rawlab[64], rawlab_ok[64];
static struct { int pos, kind, id; } RPATCH[128];
static int nrpatch;

static const struct { const char *name; int idx; } REGS[] = {
    { "AL", 0 }, { "CL", 1 }, { "DL", 2 }, { "BL", 3 }, { "AH", 4 }, { "CH", 5 }, { "DH", 6 }, { "BH", 7 },
    { "AX", 0 }, { "CX", 1 }, { "DX", 2 }, { "BX", 3 }, { "SP", 4 }, { "BP", 5 }, { "SI", 6 }, { "DI", 7 },
    { "EAX", 0 }, { "ECX", 1 }, { "EDX", 2 }, { "EBX", 3 }, { "ESP", 4 }, { "EBP", 5 }, { "ESI", 6 }, { "EDI", 7 },
    { "RAX", 0 }, { "RCX", 1 }, { "RDX", 2 }, { "RBX", 3 }, { "RSP", 4 }, { "RBP", 5 }, { "RSI", 6 }, { "RDI", 7 },
    { "R8", 8 }, { "R9", 9 }, { "R10", 10 }, { "R11", 11 }, { "R12", 12 }, { "R13", 13 }, { "R14", 14 }, { "R15", 15 },
    { "ES", 0 }, { "CS", 1 }, { "SS", 2 }, { "DS", 3 }, { "FS", 4 }, { "GS", 5 },
    { "CR0", 0 }, { "CR2", 2 }, { "CR3", 3 }, { "CR4", 4 }, { "CR8", 8 }
};
static int reg_index(const char *n) {
    for (int i = 0; i < (int)(sizeof REGS / sizeof *REGS); i++)
        if (!strcmp(REGS[i].name, n)) return REGS[i].idx;
    return -1;
}
static long cval(ASTNode *a, int line) {
    if (a && a->type == NODE_VARIABLE) {
        int r = reg_index(a->data.variable.name);
        if (r >= 0) return r;
    }
    if (!a || a->type != NODE_NUMBER) die("intrinsic argument must be a constant", line);
    return (long)a->data.number.value;
}
static void raw_defer(int kind, int id, int pos) {
    if (!raw_mode) die("raw label intrinsics are only valid in @raw mode", 0);
    if (nrpatch >= (int)(sizeof RPATCH / sizeof *RPATCH)) die("too many raw patches", 0);
    RPATCH[nrpatch].kind = kind; RPATCH[nrpatch].id = id; RPATCH[nrpatch].pos = pos; nrpatch++;
}
static void raw_apply(void) {
    for (int i = 0; i < nrpatch; i++) {
        int p = RPATCH[i].pos, id = RPATCH[i].id;
        if (id < 0 || id >= 64 || !rawlab_ok[id]) die("undefined raw label", 0);
        if (RPATCH[i].kind == 0) {
            int rel = rawlab[id] - (p + 1);
            if (rel < -128 || rel > 127) die("raw branch out of range", 0);
            code[p] = (uint8_t)rel;
        } else if (RPATCH[i].kind == 1) {
            uint16_t v = (uint16_t)(0x7C00 + rawlab[id]);
            memcpy(code + p, &v, 2);
        } else {
            uint32_t v = (uint32_t)(0x7C00 + rawlab[id]);
            memcpy(code + p, &v, 4);
        }
    }
}

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

static void rbp_disp(int reg, int off) {
    if (off >= -128 && off <= 127) EMIT(0x40 | (reg << 3) | 5, (uint8_t)off);
    else { EMIT(0x80 | (reg << 3) | 5); emit_imm(off, 4); }
}

static void mov_rax_imm(long long v) {
    if (!v) { EMIT(0x48, 0x31, 0xC0); return; }
    if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x58);
    else if (v >= 0 && v <= 0xFFFFFFFFLL) { EMIT(0xB8); emit_imm(v, 4); }
    else if (v >= -2147483648LL && v <= -1) { EMIT(0x48, 0xC7, 0xC0); emit_imm(v, 4); }  /* mov rax,imm32 */
    else { EMIT(0x48, 0xB8); emit_imm(v, 8); }
}

static int new_label(void) {
    if (nlab >= (int)(sizeof lab_pos / sizeof *lab_pos)) die("too many labels", 0);
    return nlab++;
}
static void put_label(int lab) { lab_pos[lab] = clen; }

static void emit_patch(int g, int lab) {
    if (clen + 4 > (int)sizeof code || npatch >= (int)(sizeof PATCH / sizeof *PATCH))
        die("too many jumps", 0);
    PATCH[npatch] = (typeof(PATCH[0])){ clen, lab, g };
    npatch++;
    clen += 4;
}
static void emit_rel32(int lab) { emit_patch(0, lab); }
static void emit_jmp(int lab)  { EMIT(0xE9); emit_rel32(lab); }
static void emit_jcc(int cc, int lab) { EMIT(0x0F, cc); emit_rel32(lab); } 
static void emit_call(int lab) { EMIT(0xE8); emit_rel32(lab); }

#define PE_SECT (0x40 + 4 + 20 + 240 + 40)   

static int IAT_PATCH[16], niat;
static void emit_call_iat(int slot) {
    if (niat >= (int)(sizeof IAT_PATCH / sizeof *IAT_PATCH)) die("too many IAT calls", 0);
    EMIT(0xFF, 0x15);
    IAT_PATCH[niat++] = clen * 4 | slot;
    emit_imm(0, 4);
}

typedef struct { char *name; Type *ty; int off; int reg; } Glob;
static Glob GLOB[256];
static int nglob, gsize;
static int GH[HSZ], GN[256];
static Glob *glob_find(const char *name) {
    for (int i = GH[sfnv(name) & (HSZ - 1)]; i >= 0; i = GN[i])
        if (!strcmp(GLOB[i].name, name)) return &GLOB[i];
    return NULL;
}
static void glob_hash_build(void) {
    for (int i = 0; i < HSZ; i++) GH[i] = -1;
    for (int i = nglob - 1; i >= 0; i--) { int h = sfnv(GLOB[i].name) & (HSZ - 1); GN[i] = GH[h]; GH[h] = i; }
}

static void greg_load_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x8B, (uint8_t)(0xC0 | (r & 7))); }          /* mov rax,rN */
static void greg_store_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x89, (uint8_t)(0xC0 | (r & 7))); }         /* mov rN,rax */
static void greg_load_rcx(int r) { EMIT((uint8_t)(0x48 | ((r >= 8) << 2)), 0x89, (uint8_t)(0xC0 | ((r & 7) << 3) | 1)); } /* mov rcx,rN */
static void greg_zero(int r) { EMIT((uint8_t)(0x40 | ((r >= 8) << 2) | (r >= 8)), 0x31, (uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7))); } /* xor rNd,rNd */

static void apply_patches(void) {
    for (int i = 0; i < npatch; i++) {
        int p = PATCH[i].pos, t = 0;
        int64_t rel;
        if (PATCH[i].g == 0) t = lab_pos[PATCH[i].lab];
        else if (PATCH[i].g == 1) t = lab_pos[litlab] + PATCH[i].lab;
        if (PATCH[i].g < 2) rel = t - (p + 4);
        else if (is_pe)
            rel = (int64_t)pcb + ((clen + 15) & ~15) + 176 + PATCH[i].lab - (pcb + p + 4);
        else {
            int64_t hdr = 64 + 56;
            int64_t dva = 0x400000 + hdr + clen;
            rel = dva + PATCH[i].lab - (0x400000 + hdr + p + 4);
        }
        *(int32_t *)(code + p) = (int32_t)rel;
    }
}

typedef struct { char *name; Type *ty; int off; } Loc;
static Loc LOCS[256];
static int nloc, cur_off, frame_min;
static Loc *loc_add(const char *name, Type *ty) {
    if (nloc >= (int)(sizeof LOCS / sizeof *LOCS)) die("too many locals", 0);
    cur_off -= ty_size(ty);
    if (cur_off < frame_min) frame_min = cur_off;
    LOCS[nloc] = (Loc){ (char *)name, ty, cur_off };
    return &LOCS[nloc++];
}
static Loc *loc_find(const char *name) {
    for (int i = nloc - 1; i >= 0; i--)
        if (!strcmp(LOCS[i].name, name)) return &LOCS[i];
    return NULL;
}

static struct { char *name; int lab, params; } FNS[256];
static int nfn;
static int brk_lab[64], cont_lab[64], nloop;
static int FH[HSZ], FX[256];
static int fn_find(const char *name) {
    for (int i = FH[sfnv(name) & (HSZ - 1)]; i >= 0; i = FX[i])
        if (!strcmp(FNS[i].name, name)) return i;
    return -1;
}
static void fn_hash_build(void) {
    for (int i = 0; i < HSZ; i++) FH[i] = -1;
    for (int i = nfn - 1; i >= 0; i--) { int h = sfnv(FNS[i].name) & (HSZ - 1); FX[i] = FH[h]; FH[h] = i; }
}

static int setcc_of(BinOp op) {
    return op < OP_LT ? 0x90 | op : 0x9C | (-(op - OP_LT) & 3);
}

static void emit_binop(BinOp op) {
    switch (op) {
        case OP_ADD: EMIT(0x48, 0x01, 0xC8); break;
        case OP_SUB: EMIT(0x48, 0x29, 0xC8); break;
        case OP_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC1); break;
        case OP_DIV: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9); break;
        case OP_MOD: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9, 0x48, 0x89, 0xD0); break;
        case OP_BOR:  EMIT(0x48, 0x09, 0xC8); break;
        case OP_BAND: EMIT(0x48, 0x21, 0xC8); break;
        case OP_BXOR: EMIT(0x48, 0x31, 0xC8); break;
        case OP_SHL:  EMIT(0x48, 0xD3, 0xE0); break;
        case OP_SHR:  EMIT(0x48, 0xD3, 0xF8); break;
        default:
            EMIT(0x48, 0x39, 0xC8);
            EMIT(0x0F, setcc_of(op), 0xC0);
            EMIT(0x0F, 0xB6, 0xC0);
            break;
    }
}

static int try_leaf_rcx(ASTNode *n) {
    if (n->type != NODE_VARIABLE) return 0;
    Loc *l = loc_find(n->data.variable.name);
    if (l) {
        if (l->ty->kind != 0) return 0;
        if (is_char(l->ty)) { EMIT(0x0F, 0xB6); rbp_disp(1, l->off); }
        else { EMIT(0x48, 0x8B); rbp_disp(1, l->off); }
        return 1;
    }
    Glob *g = glob_find(n->data.variable.name);
    if (!g || g->ty->kind != 0) return 0;
    if (g->reg) { greg_load_rcx(g->reg); return 1; }
    if (is_char(g->ty)) { EMIT(0x0F, 0xB6, 0x0D); emit_patch(2, g->off); }
    else { EMIT(0x48, 0x8B, 0x0D); emit_patch(2, g->off); }
    return 1;
}

static void emit_cmp_rax_imm(long long v) {
    if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xF8, (uint8_t)v);
    else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x3D); emit_imm(v, 4); }
    else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x39, 0xC8); }
}

static void emit_print_pe(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x50);
    EMIT(0x45,0x31,0xDB);
    EMIT(0x48,0x85,0xC0);
    int pos = new_label();
    emit_jcc(0x89, pos);
    EMIT(0x48,0xF7,0xD8);
    EMIT(0x41,0xBB,1,0,0,0);
    put_label(pos);
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
    EMIT(0x45,0x85,0xDB);
    int wr = new_label();
    emit_jcc(0x84, wr);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0xC6,0x06,0x2D);
    put_label(wr);
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

static void emit_print_elf(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x20);
    EMIT(0x45,0x31,0xDB);
    EMIT(0x48,0x85,0xC0);
    int pos = new_label();
    emit_jcc(0x89, pos);
    EMIT(0x48,0xF7,0xD8);
    EMIT(0x41,0xBB,1,0,0,0);
    put_label(pos);
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
    EMIT(0x45,0x85,0xDB);
    int wr = new_label();
    emit_jcc(0x84, wr);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0xC6,0x06,0x2D);
    put_label(wr);
    EMIT(0x48,0x8D,0x55,0xFF);
    EMIT(0x48,0x29,0xF2);
    EMIT(0x6A,0x01,0x58);
    EMIT(0x89,0xC7);
    EMIT(0x0F,0x05);
    EMIT(0xC9,0xC3);
}

static void emit_print_bare(void) {
    EMIT(0x55);                              /* push rbp */
    EMIT(0x48,0x89,0xE5);                    /* mov rbp, rsp */
    EMIT(0x48,0x83,0xEC,0x20);               /* sub rsp, 0x20 */
    EMIT(0x45,0x31,0xDB);                    /* xor r11d, r11d: negative flag */
    EMIT(0x48,0x85,0xC0);                    /* test rax, rax */
    int pos = new_label();
    emit_jcc(0x89, pos);                     /* js: negative */
    EMIT(0x48,0xF7,0xD8);                    /* neg rax */
    EMIT(0x41,0xBB,1,0,0,0);                 /* mov r11d, 1 */
    put_label(pos);
    EMIT(0x6A,0x0A,0x59);                    /* push 10; pop rcx */
    EMIT(0x48,0x8D,0x75,0xFF);               /* lea rsi, [rbp-1]: buffer end */
    int loop = new_label();
    put_label(loop);
    EMIT(0x48,0x31,0xD2);                    /* xor rdx, rdx */
    EMIT(0x48,0xF7,0xF1);                    /* div rcx */
    EMIT(0x80,0xC2,0x30);                    /* add dl, '0' */
    EMIT(0x48,0xFF,0xCE);                    /* dec rsi */
    EMIT(0x88,0x16);                         /* mov [rsi], dl */
    EMIT(0x48,0x85,0xC0);                    /* test rax, rax */
    emit_jcc(0x85, loop);                    /* jnz loop */
    EMIT(0x45,0x85,0xDB);                    /* test r11d, r11d */
    int wr = new_label();
    emit_jcc(0x84, wr);                      /* jz: no sign */
    EMIT(0x48,0xFF,0xCE);                    /* dec rsi */
    EMIT(0xC6,0x06,0x2D);                    /* mov byte [rsi], '-' */
    put_label(wr);
    EMIT(0x66,0xBA,0xF8,0x03);               /* mov dx, 0x3F8 (COM1) */
    int oloop = new_label();
    put_label(oloop);
    EMIT(0x48,0x39,0xEE);                    /* cmp rsi, rbp */
    int onl = new_label();
    emit_jcc(0x83, onl);                     /* jae: done */
    EMIT(0x8A,0x06);                         /* mov al, [rsi] */
    EMIT(0xEE);                              /* out dx, al */
    EMIT(0x48,0xFF,0xC6);                    /* inc rsi */
    emit_jmp(oloop);
    put_label(onl);
    EMIT(0xB0,0x0A);                         /* mov al, 10 */
    EMIT(0xEE);                              /* out dx, al */
    EMIT(0xC9,0xC3);                         /* leave; ret */
}

static void gen_expr(ASTNode*);
static void gen_stmt(ASTNode*);

static void mov_rax_imm(long long v);

static int ty_size_of_expr(ASTNode *n) {
    if (n->type == NODE_VARIABLE) {
        Loc *l = loc_find(n->data.variable.name);
        if (l) return ty_size(l->ty);
        Glob *g = glob_find(n->data.variable.name);
        if (g) return ty_size(g->ty);
        return 8;
    }
    if (n->type == NODE_STR) return 8;
    return 8;
}

static Type *ty_of_expr(ASTNode *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            Loc *l = loc_find(n->data.variable.name);
            if (l) return l->ty;
            Glob *g = glob_find(n->data.variable.name);
            return g ? g->ty : &TY_INT;
        }
        case NODE_STR:    return ty_ptr(&TY_CHAR);
        case NODE_DEREF:  return ty_of_expr(n->data.unary.value)->kind ? ty_of_expr(n->data.unary.value)->base : &TY_INT;
        case NODE_INDEX:  return ty_of_expr(n->data.index.base)->kind ? ty_of_expr(n->data.index.base)->base : &TY_INT;
        case NODE_ADDR:   return ty_ptr(ty_of_expr(n->data.unary.value));
        default:          return &TY_INT;
    }
}

static void gen_addr(ASTNode *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            Loc *l = loc_find(n->data.variable.name);
            if (l) { EMIT(0x48, 0x8D); rbp_disp(0, l->off); break; }
            Glob *g = glob_find(n->data.variable.name);
            if (!g) die("undefined variable", n->line);
            if (g->reg) die("cannot take address of a register-resident global", n->line);
            EMIT(0x48, 0x8D, 0x05);
            emit_patch(2, g->off);
            break;
        }
        case NODE_DEREF:
            gen_expr(n->data.unary.value);
            break;
        case NODE_INDEX: {
            Type *bt = ty_of_expr(n->data.index.base);
            if (bt->kind == 1) gen_expr(n->data.index.base);
            else gen_addr(n->data.index.base);
            EMIT(0x50);
            gen_expr(n->data.index.index);
            int es = ty_size(ty_of_expr(n));
            if (es == 8) EMIT(0x48, 0xC1, 0xE0, 0x03);
            else if (es != 1) { EMIT(0x48, 0x69, 0xC0); emit_imm(es, 4); }
            EMIT(0x5B, 0x48, 0x01, 0xD8);
            break;
        }
        default:
            die("not addressable", n->line);
    }
}

static void gen_expr(ASTNode *n) {
    switch (n->type) {
        case NODE_NUMBER:
            mov_rax_imm(n->data.number.value);
            break;
        case NODE_VARIABLE: {
            Loc *l = loc_find(n->data.variable.name);
            if (l) {
                if (l->ty->kind == 2) { EMIT(0x48, 0x8D); rbp_disp(0, l->off); }
                else if (is_char(l->ty)) { EMIT(0x0F, 0xB6); rbp_disp(0, l->off); }
                else { EMIT(0x48, 0x8B); rbp_disp(0, l->off); }
                break;
            }
            Glob *g = glob_find(n->data.variable.name);
            if (!g) die("undefined variable", n->line);
            if (g->reg) { greg_load_rax(g->reg); break; }  
            if (g->ty->kind == 2) { EMIT(0x48, 0x8D, 0x05); emit_patch(2, g->off); }
            else if (is_char(g->ty)) { EMIT(0x0F, 0xB6, 0x05); emit_patch(2, g->off); }
            else { EMIT(0x48, 0x8B, 0x05); emit_patch(2, g->off); }
            break;
        }
        case NODE_STR:
            EMIT(0x48, 0x8D, 0x05);
            emit_patch(1, n->data.str.off);
            break;
        case NODE_ADDR:
            gen_addr(n->data.unary.value);
            break;
        case NODE_DEREF:
            gen_expr(n->data.unary.value);
            if (is_char(ty_of_expr(n))) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        case NODE_INDEX:
            gen_addr(n);
            if (is_char(ty_of_expr(n))) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        case NODE_ASSIGN: {
            int cop = n->data.assign.cop ? n->data.assign.cop - 1 : -1;
            ASTNode *lhs = n->data.assign.lhs;
            Loc *l = NULL; Glob *g = NULL; Type *ty = NULL;
            if (lhs->type == NODE_VARIABLE) {
                l = loc_find(lhs->data.variable.name);
                if (l) ty = l->ty;
                else { g = glob_find(lhs->data.variable.name); if (g) ty = g->ty; }
            }
            if (g && g->reg) {
                int r = g->reg;
                gen_expr(n->data.assign.rhs);
                if (cop < 0) { greg_store_rax(r); break; }
                int sync = 1;
                switch (cop) {
                    case OP_ADD: EMIT((uint8_t)(0x48 | (r >= 8)), 0x01, (uint8_t)(0xC0 | (r & 7))); break;   /* add  rN,rax */
                    case OP_SUB: EMIT((uint8_t)(0x48 | (r >= 8)), 0x29, (uint8_t)(0xC0 | (r & 7))); break;   /* sub  rN,rax */
                    case OP_MUL: EMIT(0x4C, 0x0F, 0xAF, (uint8_t)(0xC0 | ((r & 7) << 3))); break;           /* imul rN,rax */
                    default: { 
                        greg_load_rcx(r);
                        greg_store_rax(r);
                        EMIT(0x48, 0x89, 0xC8);                          /* mov rax,rcx */
                        EMIT(0x48, 0x99);                                /* cqo */
                        EMIT((uint8_t)(0x48 | (r >= 8)), 0xF7, (uint8_t)(0xC0 | 0x38 | (r & 7)));  /* idiv rN */
                        if (cop == OP_MOD) EMIT(0x48, 0x89, 0xD0);       /* mov rax,rdx */
                        greg_store_rax(r);
                        sync = 0;
                        break;
                    }
                }
                if (sync) greg_load_rax(r);      
                break;
            }
            if (ty && ty->kind == 0 && (cop < 0 || (!is_char(ty) && (cop == OP_ADD || cop == OP_SUB)))) {
                gen_expr(n->data.assign.rhs);
                if (cop < 0) {
                    if (l) { EMIT(is_char(ty) ? 0x88 : 0x48, 0x89); rbp_disp(0, l->off); }
                    else { EMIT(is_char(ty) ? 0x88 : 0x48, 0x89, 0x05); emit_patch(2, g->off); }
                } else {
                    int opc = cop == OP_ADD ? 0x01 : 0x29;
                    if (l) { EMIT(0x48, opc); rbp_disp(0, l->off); }
                    else { EMIT(0x48, opc, 0x05); emit_patch(2, g->off); }
                }
                break;
            }
            gen_addr(lhs);
            EMIT(0x50);
            gen_expr(n->data.assign.rhs);
            EMIT(0x5B);
            if (cop >= 0) {
                EMIT(0x48, 0x8B, 0x0B);
                EMIT(0x48, 0x91);
                switch (cop) {
                    case OP_ADD: EMIT(0x48, 0x01, 0xC8); break;
                    case OP_SUB: EMIT(0x48, 0x29, 0xC8); break;
                    case OP_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC1); break;
                    case OP_DIV: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9); break;
                    case OP_MOD: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9, 0x48, 0x89, 0xD0); break;
                }
            }
            if (is_char(ty_of_expr(lhs))) EMIT(0x88, 0x03);
            else EMIT(0x48, 0x89, 0x03);
            break;
        }
        case NODE_SIZEOF:
            mov_rax_imm(ty_size_of_expr(n->data.unary.value));
            break;
        case NODE_NOT:
            gen_expr(n->data.unary.value);
            EMIT(0x48, 0x85, 0xC0);             /* test rax,rax */
            EMIT(0x0F, 0x94, 0xC0);             /* sete al */
            EMIT(0x0F, 0xB6, 0xC0);             /* movzx rax,al */
            break;
        case NODE_BNOT:
            gen_expr(n->data.unary.value);
            EMIT(0x48, 0xF7, 0xD0);             /* not rax */
            break;
        case NODE_BINARY: {
            BinOp op = n->data.binary.op;
            ASTNode *r = n->data.binary.right;
            if (op == OP_AND || op == OP_OR) {
                int lab_sc = new_label(), lab_end = new_label();
                int cc = op == OP_AND ? 0x84 : 0x85;   
                int v_norm = op == OP_AND ? 1 : 0;    
                gen_expr(n->data.binary.left);
                EMIT(0x48, 0x85, 0xC0);
                emit_jcc(cc, lab_sc);
                gen_expr(r);
                EMIT(0x48, 0x85, 0xC0);
                emit_jcc(cc, lab_sc);
                mov_rax_imm(v_norm);
                emit_jmp(lab_end);
                put_label(lab_sc);
                mov_rax_imm(1 - v_norm);
                put_label(lab_end);
                break;
            }
            if (r->type == NODE_NUMBER) {
                long long v = r->data.number.value;
                gen_expr(n->data.binary.left);
                switch (op) {
                    case OP_ADD:
                        if (v) {
                            if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xC0, (uint8_t)v);
                            else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x05); emit_imm(v, 4); }
                            else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x01, 0xC8); }
                        }
                        break;
                    case OP_SUB:
                        if (v) {
                            if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xE8, (uint8_t)v);
                            else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x2D); emit_imm(v, 4); }
                            else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x29, 0xC8); }
                        }
                        break;
                    case OP_MUL:
                        if (v == 1) break;
                        if (!v) { EMIT(0x48, 0x31, 0xC0); break; }
                        if (v >= -128 && v <= 127) EMIT(0x48, 0x6B, 0xC0, (uint8_t)v);
                        else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x69, 0xC0); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x0F, 0xAF, 0xC1); }
                        break;
                    case OP_DIV:
                    case OP_MOD:
                        EMIT(0x48, 0x99);
                        if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x59);
                        else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0xC7, 0xC1); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); }
                        EMIT(0x48, 0xF7, 0xF9);
                        if (op == OP_MOD) EMIT(0x48, 0x89, 0xD0);
                        break;
                    case OP_BOR:
                        if (!v) break;
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x0D); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x09, 0xC8); }
                        break;
                    case OP_BAND:
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x25); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x21, 0xC8); }
                        break;
                    case OP_BXOR:
                        if (!v) break;
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x35); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x31, 0xC8); }
                        break;
                    case OP_SHL:
                        EMIT(0x48, 0xC1, 0xE0, (uint8_t)(v & 63)); break;
                    case OP_SHR:
                        EMIT(0x48, 0xC1, 0xF8, (uint8_t)(v & 63)); break;
                    default:
                        emit_cmp_rax_imm(v);
                        EMIT(0x0F, setcc_of(op), 0xC0);
                        EMIT(0x0F, 0xB6, 0xC0);
                        break;
                }
                break;
            }
            gen_expr(n->data.binary.left);
            if (try_leaf_rcx(r)) { emit_binop(op); break; }
            EMIT(0x50);
            gen_expr(r);
            EMIT(0x59);
            EMIT(0x48, 0x91);
            emit_binop(op);
            break;
        }
        case NODE_CALL: {
            const char *nm = n->data.call.name;
            int ac = n->data.call.acount;
            if (!strcmp(nm, "asm")) {
                for (int i = 0; i < ac; i++) {
                    ASTNode *a = n->data.call.args[i];
                    if (a->type != NODE_NUMBER) die("asm() args must be constants", n->line);
                    EMIT((uint8_t)a->data.number.value);
                }
                EMIT(0x31, 0xC0);
                break;
            }
            if (!strcmp(nm, "cli"))   { EMIT(0xFA); break; }
            if (!strcmp(nm, "sti"))   { EMIT(0xFB); break; }
            if (!strcmp(nm, "hlt"))   { EMIT(0xF4); break; }
            if (!strcmp(nm, "iretq")) { EMIT(0x48, 0xCF); break; }
            if (!strcmp(nm, "lgdt") || !strcmp(nm, "lidt") || !strcmp(nm, "setcr3")) {
                if (ac != 1) die("intrinsic needs 1 argument", n->line);
                if (!strcmp(nm, "setcr3") && !bin_fmt) die("intrinsic is only available in bin output", n->line);
                gen_expr(n->data.call.args[0]);
                if (!strcmp(nm, "lgdt")) EMIT(0x0F, 0x01, 0x10);        /* lgdt [rax] */
                else if (!strcmp(nm, "lidt")) EMIT(0x0F, 0x01, 0x18);   /* lidt [rax] */
                else EMIT(0x0F, 0x22, 0xD8);                            /* mov cr3,rax */
                break;
            }
            if (!strcmp(nm, "inb") || !strcmp(nm, "inl")) {
                if (ac != 1) die("inb(port)", n->line);
                ASTNode *a = n->data.call.args[0];
                if (a->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(a->data.number.value, 2); }
                else { gen_expr(a); EMIT(0x66, 0x89, 0xC2); }           /* mov dx,ax */
                if (nm[2] == 'l') EMIT(0xED);                           /* in eax,dx */
                else { EMIT(0xEC); EMIT(0x0F, 0xB6, 0xC0); }            /* in al,dx; movzx */
                break;
            }
            if (!strcmp(nm, "outb") || !strcmp(nm, "outl")) {
                if (ac != 2) die("outb(port, value)", n->line);
                ASTNode *pa = n->data.call.args[0];
                gen_expr(n->data.call.args[1]);
                EMIT(0x50);                                             /* push rax */
                if (pa->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(pa->data.number.value, 2); }
                else { gen_expr(pa); EMIT(0x66, 0x89, 0xC2); }          /* mov dx,ax */
                EMIT(0x58);                                             /* pop rax */
                EMIT(nm[3] == 'l' ? 0xEF : 0xEE);                       /* out dx,eax / out dx,al */
                break;
            }
            {
                int ri = -1;
                for (int k = 0; k < (int)(sizeof RINAME / sizeof *RINAME); k++)
                    if (!strcmp(nm, RINAME[k])) { ri = k; break; }
                if (ri < 0) goto not_intrinsic;
                if (ac != RINARG[ri]) die("intrinsic: wrong argument count", n->line);
                if (((0x71FFu >> ri) & 1) && !bin_fmt) die("intrinsic is only available in bin output", n->line);
                long a0 = ac > 0 ? cval(n->data.call.args[0], n->line) : 0;
                long a1 = ac > 1 ? cval(n->data.call.args[1], n->line) : 0;
                switch (ri) {
                case RI_MOVB:  EMIT(0xB0 + (a0 & 7), (uint8_t)a1); break;
                case RI_MOVW:  EMIT(0xB8 + (a0 & 7)); emit_imm(a1, 2); break;
                case RI_MOVL:  EMIT(0xB8 + (a0 & 7)); emit_imm(a1, 4); break;
                case RI_MOVQ:  EMIT(0x48, 0xC7, 0xC0 + (a0 & 7)); emit_imm(a1, 4); break;
                case RI_XORW:
                case RI_XORL:  EMIT(0x31, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RI_MOVSREG: EMIT(0x8E, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RI_ORB:   EMIT(0x0C + (a0 & 7), (uint8_t)a1); break;
                case RI_ORL:   EMIT(0x0D + (a0 & 7)); emit_imm(a1, 4); break;
                case RI_INTN:  EMIT(0xCD, (uint8_t)a0); break;
                case RI_INAL:  EMIT(0xE4, (uint8_t)a0); break;
                case RI_OUTAL: EMIT(0xE6, (uint8_t)a0); break;
                case RI_CRRD:  EMIT(0x0F, 0x20, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RI_CRWR:  EMIT(0x0F, 0x22, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RI_ST32:  EMIT(0xC7, 0x05); emit_imm(a0, 4); emit_imm(a1, 4); break;
                case RI_CLD:   EMIT(0xFC); break;
                case RI_RDMSR: EMIT(0x0F, 0x32); break;
                case RI_WRMSR: EMIT(0x0F, 0x30); break;
                case RI_REPMOVSQ: EMIT(0xF3, 0x48, 0xA5); break;
                case RI_JMPRAX: EMIT(0xFF, 0xE0); break;
                case RI_LABEL:
                    if (!raw_mode) die("label() is only valid in @raw mode", n->line);
                    if (a0 < 0 || a0 >= 64) die("raw label id out of range", n->line);
                    rawlab[a0] = clen; rawlab_ok[a0] = 1;
                    break;
                case RI_JC:   EMIT(0x72, 0); raw_defer(0, (int)a0, clen - 1); break;
                case RI_JMP:  EMIT(0xEB, 0); raw_defer(0, (int)a0, clen - 1); break;
                case RI_LJMP16: EMIT(0xEA); raw_defer(1, (int)a1, clen); emit_imm(0, 2); emit_imm(a0, 2); break;
                case RI_LJMP32: EMIT(0xEA); raw_defer(2, (int)a1, clen); emit_imm(0, 4); emit_imm(a0, 2); break;
                case RI_LGDTAT: EMIT(0x0F, 0x01, 0x16); raw_defer(1, (int)a0, clen); emit_imm(0, 2); break;
                case RI_GDTDESC: emit_imm(a1 - 1, 2); raw_defer(2, (int)a0, clen); emit_imm(0, 4); break;
                }
                break;
            }
        not_intrinsic:
            if (!strcmp(nm, "syscall")) {
                if (n->data.call.acount < 1 || n->data.call.args[0]->type != NODE_NUMBER)
                    die("syscall(nr, a, b, c)", n->line);
                long nr = n->data.call.args[0]->data.number.value;
                if (is_pe) {
                    if (nr != 60) die("syscall: only exit(60) on PE", n->line);
                    gen_expr(n->data.call.args[1]);
                    EMIT(0x48, 0x89, 0xC1);
                    emit_call_iat(2);
                    break;
                }
                if (n->data.call.acount != 4) die("syscall(nr, a, b, c)", n->line);
                for (int i = 3; i >= 1; i--) { gen_expr(n->data.call.args[i]); EMIT(0x50); }
                EMIT(0x5F, 0x5E, 0x5A);
                mov_rax_imm(nr);
                EMIT(0x0F, 0x05);
                break;
            }
            int f = fn_find(n->data.call.name);
            if (f < 0) { fprintf(stderr, "error (line %d): unknown func %s\n", n->line, n->data.call.name); exit(1); }
            if (ac != FNS[f].params) {
                fprintf(stderr, "error (line %d): %s expects %d args, got %d\n",
                        n->line, n->data.call.name, FNS[f].params, ac);
                exit(1);
            }
            if (ac == 0) {
                emit_call(FNS[f].lab);
            } else if (ac == 1) {
                gen_expr(n->data.call.args[0]);
                EMIT(0x48, 0x89, 0xC7);
                emit_call(FNS[f].lab);
            } else {
                int pad = ((ac - 1) & 1) ? 8 : 0;
                if (pad) EMIT(0x48, 0x83, 0xEC, 0x08);
                for (int i = ac - 1; i >= 1; i--) { gen_expr(n->data.call.args[i]); EMIT(0x50); }
                gen_expr(n->data.call.args[0]);
                EMIT(0x48, 0x89, 0xC7);
                emit_call(FNS[f].lab);
                long popb = 8L * (ac - 1) + pad;
                if (popb < 128) EMIT(0x48, 0x83, 0xC4, (uint8_t)popb);
                else { EMIT(0x48, 0x81, 0xC4); emit_imm(popb, 4); }
            }
            break;
        }
        default:
            die("unsupported expression", n->line);
    }
}

static int gen_cond(ASTNode *c) {
    if (c->type == NODE_BINARY && c->data.binary.op >= OP_EQ && c->data.binary.op <= OP_GE) {
        ASTNode *r = c->data.binary.right;
        gen_expr(c->data.binary.left);
        if (r->type == NODE_NUMBER) emit_cmp_rax_imm(r->data.number.value);
        else if (try_leaf_rcx(r)) EMIT(0x48, 0x39, 0xC8);
        else { EMIT(0x50); gen_expr(r); EMIT(0x59); EMIT(0x48, 0x39, 0xC1); }
        return ((setcc_of(c->data.binary.op) & 15) | 0x80) ^ 1;
    }
    gen_expr(c);
    EMIT(0x48, 0x85, 0xC0);
    return 0x84;
}

static void gen_stmt(ASTNode *n) {
    switch (n->type) {
        case NODE_LET: {
            if (n->data.let.value) gen_expr(n->data.let.value);
            Loc *l = loc_add(n->data.let.name, n->data.let.ty);
            if (n->data.let.ty->kind == 2) {
                EMIT(0x48, 0x8D); rbp_disp(7, l->off);
                if (n->data.let.value) EMIT(0x48, 0x89, 0x07);
                else {
                    Type *e = n->data.let.ty->base;
                    EMIT(0x48, 0x31, 0xC0);
                    EMIT(0xB9); emit_imm(is_char(e) ? ty_size(n->data.let.ty) : ty_size(n->data.let.ty) / 8, 4);
                    if (is_char(e)) EMIT(0xF3, 0xAA); else EMIT(0xF3, 0x48, 0xAB);
                }
            } else {
                if (!n->data.let.value) die("missing initializer", n->line);
                if (is_char(n->data.let.ty)) { EMIT(0x88); rbp_disp(0, l->off); }
                else { EMIT(0x48, 0x89); rbp_disp(0, l->off); }
            }
            break;
        }
        case NODE_PRINT:
            if (freestanding && !boot_mode) die("print is unavailable in freestanding mode", n->line);
            gen_expr(n->data.print.value);    
            EMIT(0xE8);
            if (boot_mode) emit_patch(0, printlab);
            else emit_imm(-(clen + 4), 4);
            break;
        case NODE_BLOCK: {
            int sn = nloc, so = cur_off;
            for (int i = 0; i < n->data.block.count; i++) gen_stmt(n->data.block.stmts[i]);
            nloc = sn; cur_off = so;
            break;
        }
        case NODE_IF: {
            int lab_else = new_label(), lab_end = new_label();
            emit_jcc(gen_cond(n->data.if_node.cond), lab_else);
            int sn = nloc, so = cur_off;
            gen_stmt(n->data.if_node.then);
            nloc = sn; cur_off = so;
            emit_jmp(lab_end);
            put_label(lab_else);
            if (n->data.if_node.else_) {
                gen_stmt(n->data.if_node.else_);
                nloc = sn; cur_off = so;
            }
            put_label(lab_end);
            break;
        }
        case NODE_WHILE: {
            int lab_start = new_label(), lab_end = new_label();
            if (nloop >= 64) die("loops too deep", n->line);
            brk_lab[nloop] = lab_end; cont_lab[nloop] = lab_start; nloop++;
            put_label(lab_start);
            emit_jcc(gen_cond(n->data.while_node.cond), lab_end);
            int sn = nloc, so = cur_off;
            gen_stmt(n->data.while_node.body);
            nloc = sn; cur_off = so;
            emit_jmp(lab_start);
            put_label(lab_end);
            nloop--;
            break;
        }
        case NODE_BREAK:
            if (!nloop) die("break outside loop", n->line);
            emit_jmp(brk_lab[nloop - 1]);
            break;
        case NODE_CONTINUE:
            if (!nloop) die("continue outside loop", n->line);
            emit_jmp(cont_lab[nloop - 1]);
            break;
        case NODE_RETURN:
            gen_expr(n->data.return_node.value);
            EMIT(0xC9, 0xC3);                  
            break;
        default:
            gen_expr(n); 
            break;
    }
}

static int emit_prologue(void) {
    EMIT(0x55, 0x48,0x89,0xE5, 0x48,0x81,0xEC);
    int p = clen;
    emit_imm(0, 4);
    return p;
}

static void patch_prologue(int p) {
    int need = (-frame_min + 32 + 15) & ~15;
    if (need < 32) need = 32;
    *(int32_t *)(code + p) = need;
}

static int needs_frame(ASTNode *n) {
    if (!n) return 0;
    if (n->type == NODE_LET) return 1;
    if (n->type == NODE_BLOCK) {
        for (int i = 0; i < n->data.block.count; i++)
            if (needs_frame(n->data.block.stmts[i])) return 1;
        return 0;
    }
    if (n->type == NODE_IF) return needs_frame(n->data.if_node.then) || needs_frame(n->data.if_node.else_);
    if (n->type == NODE_WHILE) return needs_frame(n->data.while_node.body);
    return 0;
}

#define GREG_NREG 4
static int grefs[256], gbad[256];

static void scan_node(ASTNode *n, int w) {
    if (!n || w <= 0) return;
    switch (n->type) {
        case NODE_VARIABLE: {
            Glob *g = glob_find(n->data.variable.name);
            if (g) grefs[g - GLOB] += w;
            break;
        }
        case NODE_ADDR: {
            ASTNode *v = n->data.unary.value;
            if (v->type == NODE_VARIABLE) {
                Glob *g = glob_find(v->data.variable.name);
                if (g) gbad[g - GLOB] = 1;
            } else scan_node(v, w);
            break;
        }
        case NODE_NUMBER: case NODE_STR: case NODE_SIZEOF: break;   
        case NODE_NOT: case NODE_DEREF: case NODE_BNOT:
            scan_node(n->data.unary.value, w);
            break;
        case NODE_BINARY:
            scan_node(n->data.binary.left, w);
            scan_node(n->data.binary.right, w);
            break;
        case NODE_ASSIGN:
            scan_node(n->data.assign.lhs, w);     
            scan_node(n->data.assign.rhs, w);
            break;
        case NODE_LET:    scan_node(n->data.let.value, w); break;
        case NODE_PRINT:  scan_node(n->data.print.value, w); break;
        case NODE_RETURN: scan_node(n->data.return_node.value, w); break;
        case NODE_INDEX:
            scan_node(n->data.index.base, w);
            scan_node(n->data.index.index, w);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) scan_node(n->data.call.args[i], w);
            break;
        case NODE_BLOCK:
            for (int i = 0; i < n->data.block.count; i++) scan_node(n->data.block.stmts[i], w);
            break;
        case NODE_IF:
            scan_node(n->data.if_node.cond, w);
            scan_node(n->data.if_node.then, w);
            scan_node(n->data.if_node.else_, w);
            break;
        case NODE_WHILE:
            scan_node(n->data.while_node.cond, w * 8);
            scan_node(n->data.while_node.body, w * 8);
            break;
        case NODE_FUNCTION: scan_node(n->data.function.body, w); break;
        default: break;
    }
}

static void pick_glob_regs(ASTNode *root) {
    static const int RV[GREG_NREG] = { 12, 13, 14, 15 };
    scan_node(root, 1);
    for (int k = 0; k < GREG_NREG; k++) {
        int best = -1;
        for (int i = 0; i < nglob; i++) {
            if (GLOB[i].reg || gbad[i] || !grefs[i]) continue;
            if (GLOB[i].ty->kind == 2 || GLOB[i].ty->sz != 8) continue;  
            if (best < 0 || grefs[i] > grefs[best]) best = i;
        }
        if (best < 0) return;
        GLOB[best].reg = RV[k];
        if (getenv("LGC_DUMP_GREG"))
            fprintf(stderr, "[greg] %-12s -> r%-2d weight=%-6d off=%d\n",
                    GLOB[best].name, RV[k], grefs[best], GLOB[best].off);
    }
}

static void emit_entry(ASTNode *root) {
    for (int i = 0; i < nglob; i++)
        if (GLOB[i].reg) greg_zero(GLOB[i].reg);
    if (!freestanding) {
        for (int i = 0; i < 8; i++) {
            char nm[8];
            sprintf(nm, "argv%d", i + 1);
            Glob *a = glob_find(nm);
            if (!a) continue;
            EMIT(0x48, 0x8B, 0x44, 0x24, (uint8_t)(0x10 + 8 * i));
            if (a->reg) { greg_store_rax(a->reg); continue; }
            EMIT(0x48, 0x89, 0x05);
            emit_patch(2, a->off);
        }
    }

    int toplet = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type != NODE_FUNCTION && n->type != NODE_LET && needs_frame(n)) toplet = 1;
    }
    int epp = 0;
    if (toplet) epp = emit_prologue();
    nloc = 0; cur_off = 0; frame_min = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION) continue;
        if (n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
        if (n->type == NODE_LET) {
            if (!n->data.let.value) continue;
            Glob *g = glob_find(n->data.let.name);
            gen_expr(n->data.let.value);
            if (g && g->reg) { greg_store_rax(g->reg); continue; }   
            EMIT(0x50);
            EMIT(0x48, 0x8D, 0x1D);
            emit_patch(2, g->off);
            EMIT(0x58);
            if (is_char(g->ty)) EMIT(0x88, 0x03);
            else EMIT(0x48, 0x89, 0x03);
            continue;
        }
        gen_stmt(n);
    }
    int mi = fn_find(entry_name ? entry_name : "main");
    if (mi >= 0) {
        EMIT(0xE8); emit_patch(0, FNS[mi].lab);   /* call entry function */
        if (freestanding) EMIT(0xEB, 0xFE);       /* jmp $ */
        else if (is_pe) {
            EMIT(0x48, 0x89, 0xC1);               /* mov rcx, rax (exit code) */
            emit_call_iat(2);
        } else {
            EMIT(0x48, 0x89, 0xC7);               /* mov rdi, rax (exit code) */
            mov_rax_imm(60);
            EMIT(0x0F, 0x05);
        }
    } else if (freestanding) {
        EMIT(0xEB, 0xFE);
    } else if (is_pe) {
        EMIT(0x31, 0xC9);
        emit_call_iat(2);
    } else {
        mov_rax_imm(60);
        EMIT(0x31, 0xFF);
        EMIT(0x0F, 0x05);
    }
    if (toplet) patch_prologue(epp);
}

static void generate_code(ASTNode *root) {
    bin_fmt = (fmt == FMT_BIN);
    clen = 0;
    glob_hash_build();
    fn_hash_build();
    if (raw_mode) {
        litlab = new_label();
        for (int i = 0; i < root->data.block.count; i++) {
            ASTNode *n = root->data.block.stmts[i];
            if (n->type == NODE_FUNCTION) continue;
            if (n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
            gen_stmt(n);
        }
        entry = 0;
        put_label(litlab);
        raw_apply();
        apply_patches();
        return;
    }
    if (!freestanding) { if (is_pe) emit_print_pe(); else emit_print_elf(); }
    litlab = new_label();

    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        if (nglob >= (int)(sizeof GLOB / sizeof *GLOB)) die("too many globals", n->line);
        GLOB[nglob] = (typeof(GLOB[0])){ n->data.let.name, n->data.let.ty, gsize, 0 };
        gsize += ty_size(n->data.let.ty);
        nglob++;
    }
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        if (nfn >= (int)(sizeof FNS / sizeof *FNS)) die("too many functions", f->line);
        FNS[nfn] = (typeof(FNS[0])){ f->data.function.name, new_label(), f->data.function.pcount };
        nfn++;
    }
    glob_hash_build();
    fn_hash_build();
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_EXTERN_FUNC) {
            int f = fn_find(n->data.extfn.name);
            if (f < 0) die("extern func has no definition", n->line);
            if (FNS[f].params != n->data.extfn.pcount) die("extern func arity mismatch", n->line);
        } else if (n->type == NODE_EXTERN_GLOB) {
            if (!glob_find(n->data.extgl.name)) die("extern let has no definition", n->line);
        }
    }

    pick_glob_regs(root);

    if (bin_fmt) { entry = clen; emit_entry(root); }

    if (boot_mode) {
        printlab = new_label();
        put_label(printlab);
        emit_print_bare();
    }

    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        put_label(FNS[fn_find(f->data.function.name)].lab);
        int pp = emit_prologue();
        nloc = 0; cur_off = 0; frame_min = 0;
        if (f->data.function.pcount > 0) {
            EMIT(0x48, 0x89, 0xF8);
            int off = loc_add(f->data.function.params[0], &TY_INT)->off;
            EMIT(0x48, 0x89); rbp_disp(0, off);
        }
        for (int k = 1; k < f->data.function.pcount; k++) {
            int off = loc_add(f->data.function.params[k], &TY_INT)->off;
            EMIT(0x48, 0x8B); rbp_disp(0, 16 + 8 * (k - 1));
            EMIT(0x48, 0x89); rbp_disp(0, off);
        }
        gen_stmt(f->data.function.body);
        EMIT(0xC9, 0xC3);
        patch_prologue(pp);
    }

    if (!bin_fmt) { entry = clen; emit_entry(root); }

    put_label(litlab);
    if (nlit) { memcpy(code + clen, LIT, nlit); clen += nlit; }
    pcb = (PE_SECT + 15) & ~15;
    if (is_pe) {
        apply_patches();
        uint32_t imp_rva = pcb + ((clen + 15) & ~15);
        for (int i = 0; i < niat; i++) {
            int pos = IAT_PATCH[i] >> 2, slot = IAT_PATCH[i] & 3;
            *(int32_t *)(code + pos) = imp_rva + 72 + (slot << 3) - (pcb + pos + 4);
        }
    } else {
        apply_patches();
    }
}

static void write_elf(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint64_t hdr_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    const uint64_t base = (uint64_t)load_base;

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
        .p_flags = PF_R | PF_W | PF_X,
        .p_offset = 0,
        .p_vaddr = base,
        .p_paddr = base,
        .p_filesz = hdr_size + clen,
        .p_memsz = hdr_size + clen + gsize,
        .p_align = 0x1000,
    };

    write(fd, &ehdr, sizeof ehdr);
    write(fd, &phdr, sizeof phdr);
    write(fd, code, clen);
    close(fd);
}

static const uint8_t BOOT_SEC[271] = {
    0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c,
    0xb8, 0x00, 0x10, 0x8e, 0xc0, 0x31, 0xdb, 0xb4, 0x02, 0xb0, 0x10, 0xb5,
    0x00, 0xb1, 0x02, 0xb6, 0x00, 0xcd, 0x13, 0x72, 0x18, 0xe4, 0x92, 0x0c,
    0x02, 0xe6, 0x92, 0x0f, 0x01, 0x16, 0x09, 0x7d, 0x0f, 0x20, 0xc0, 0x0c,
    0x01, 0x0f, 0x22, 0xc0, 0xea, 0x3c, 0x7c, 0x08, 0x00, 0xf4, 0xeb, 0xfd,
    0xb8, 0x10, 0x00, 0x00, 0x00, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc,
    0x00, 0x7c, 0x00, 0x00, 0xc7, 0x05, 0x00, 0x10, 0x00, 0x00, 0x03, 0x20,
    0x00, 0x00, 0xc7, 0x05, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc7, 0x05, 0x00, 0x20, 0x00, 0x00, 0x03, 0x30, 0x00, 0x00, 0xc7, 0x05,
    0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x05, 0x00, 0x30,
    0x00, 0x00, 0x83, 0x00, 0x00, 0x00, 0xc7, 0x05, 0x04, 0x30, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0f, 0x20, 0xe0, 0x0d, 0x20, 0x00, 0x00, 0x00,
    0x0f, 0x22, 0xe0, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x0f, 0x22, 0xd8, 0xb9,
    0x80, 0x00, 0x00, 0xc0, 0x0f, 0x32, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x0f,
    0x30, 0x0f, 0x20, 0xc0, 0x0d, 0x01, 0x00, 0x00, 0x80, 0x0f, 0x22, 0xc0,
    0xea, 0xbb, 0x7c, 0x00, 0x00, 0x18, 0x00, 0xb8, 0x10, 0x00, 0x00, 0x00,
    0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0x48, 0xc7, 0xc4, 0x00, 0x00, 0x08,
    0x00, 0xfc, 0xbe, 0x00, 0x00, 0x01, 0x00, 0xbf, 0x00, 0x00, 0x10, 0x00,
    0xb9, 0x00, 0x04, 0x00, 0x00, 0xf3, 0x48, 0xa5, 0xb8, 0x00, 0x00, 0x10,
    0x00, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x92, 0xcf, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xaf, 0x00, 0x31,
    0xc0, 0x1f, 0x00, 0xe7, 0x7c, 0x00, 0x00
};

static void write_bin(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }
    if (boot_mode) {
        static uint8_t z[8192];
        if (clen + gsize > 8192) {
            fprintf(stderr, "error: kernel image exceeds 8192 bytes (%d)\n", clen + gsize);
            exit(1);
        }
        write(fd, BOOT_SEC, sizeof BOOT_SEC);
        write(fd, z, 510 - (int)sizeof BOOT_SEC);
        write(fd, "\x55\xAA", 2);
        write(fd, code, clen);
        if (gsize > 0) write(fd, z, gsize);
        write(fd, z, 8192 - clen - gsize);
        close(fd);
        printf("  boot disk: 512-byte boot sector + %d bytes kernel (%d code + %d bss) = %d bytes\n",
               clen + gsize, clen, gsize, 512 + 8192);
        return;
    }
    if (raw_mode) {
        static uint8_t z[512];
        if (clen > 510) { fprintf(stderr, "error: raw boot sector exceeds 510 bytes (%d)\n", clen); exit(1); }
        write(fd, code, clen);
        if (clen < 510) write(fd, z, 510 - clen);
        write(fd, "\x55\xAA", 2);
        close(fd);
        printf("  raw boot sector: %d bytes code + %d pad + 55 AA = 512\n", clen, 510 - clen);
        return;
    }
    write(fd, code, clen);
    if (gsize > 0) {
        static uint8_t z[4096];
        for (int left = gsize; left > 0; ) {
            int n = left < (int)sizeof z ? left : (int)sizeof z;
            write(fd, z, n);
            left -= n;
        }
    }
    close(fd);
    printf("  flat binary: entry +0x%x, load 0x%llx, %d bytes (code %d + bss %d)\n",
           entry, load_base, clen + gsize, clen, gsize);
}

static void put(uint8_t *p, uint64_t v, int n) { memcpy(p, &v, n); }

static void write_pe(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint32_t body = (clen + 15) & ~15;
    const uint32_t imp_rva = pcb + body;
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
    put(h + 0x68, pcb + entry, 4);
    put(h + 0x6C, pcb, 4);
    put(h + 0x70, 0x400000, 8);
    put(h + 0x78, 0x10, 4);
    put(h + 0x7C, 0x10, 4);
    put(h + 0x88, 6, 2);
    put(h + 0x90, pcb + vsize + ((gsize + 15) & ~15), 4);
    put(h + 0x94, pcb, 4);
    put(h + 0x9C, 3, 2);
    put(h + 0xA0, 0x100000, 8);
    put(h + 0xA8, 0x1000, 8);
    put(h + 0xB0, 0x100000, 8);
    put(h + 0xB8, 0x1000, 8);
    put(h + 0xC4, 16, 4);
    put(h + 0xD0, imp_rva, 4);
    put(h + 0xD4, 40, 4);
    put(h + 0x150, vsize + gsize, 4);
    put(h + 0x154, pcb, 4);
    put(h + 0x158, vsize, 4);
    put(h + 0x15C, pcb, 4);
    put(h + 0x16C, gsize ? 0xE00000E0 : 0x60000020, 4);

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

    write(fd, h, pcb);
    write(fd, code, clen);
    if (body > (uint32_t)clen) write(fd, zero, body - clen);
    write(fd, imp, 176);
    close(fd);
}

enum { MAX_IMPORT = 64 };
static char IMPORTED[MAX_IMPORT][512];
static int nimported;

static int import_seen(const char *p) {
    for (int i = 0; i < nimported; i++)
        if (!strcmp(IMPORTED[i], p)) return 1;
    return 0;
}
static void import_mark(const char *p) {
    if (nimported >= MAX_IMPORT) die("too many imports", 0);
    strncpy(IMPORTED[nimported], p, 511);
    IMPORTED[nimported][511] = 0;
    nimported++;
}
static void resolve_path(const char *cur, const char *name, char *out) {
    if (name[0] == '/') { snprintf(out, 4096, "%s", name); return; }
    const char *s = strrchr(cur, '/');
    if (!s) snprintf(out, 4096, "%s", name);
    else snprintf(out, 4096, "%.*s/%s", (int)(s - cur), cur, name);
}

static Token *lex_source(const char *path, int *out_n) {
    FILE *sf = fopen(path, "rb");
    if (!sf) { perror(path); exit(1); }
    fseek(sf, 0, SEEK_END);
    long size = ftell(sf);
    rewind(sf);
    char *src = malloc(size + 1);
    if (!src || fread(src, 1, size, sf) != (size_t)size) { fprintf(stderr, "Cannot read %s\n", path); exit(1); }
    src[size] = 0;
    fclose(sf);
    Lexer lx = { src, 0, 1 };
    Token *tokens = NULL;
    int tcnt = 0, tcap = 0;
    Token tk;
    do {
        tk = next_token(&lx);
        PUSH(tokens, tcnt, tcap, tk);
    } while (tk.type != TOK_EOF && tk.type != TOK_ERROR);
    if (tk.type == TOK_ERROR) { fprintf(stderr, "Lex error in %s\n", path); exit(1); }
    free(src);
    *out_n = tcnt;
    return tokens;
}

static void load_tokens(const char *path, Token **tokens, int *tcnt, int *tcap) {
    int n = 0;
    Token *t = lex_source(path, &n);
    for (int i = 0; i < n; i++) {
        if (t[i].type == TOK_EOF) continue;
        if (t[i].type == TOK_AT && i + 3 < n && t[i + 1].type == TOK_IDENTIFIER &&
            !strcmp(t[i + 1].text, "import") && t[i + 2].type == TOK_STR &&
            t[i + 3].type == TOK_SEMICOLON) {
            const char *s = t[i + 2].text;
            int len = (int)strlen(s);
            char nm[512], full[4096];
            if (len >= 2) snprintf(nm, sizeof nm, "%.*s", len - 2, s + 1);
            else nm[0] = 0;
            resolve_path(path, nm, full);
            if (!import_seen(full)) { import_mark(full); load_tokens(full, tokens, tcnt, tcap); }
            i += 3;
            continue;
        }
        PUSH(*tokens, *tcnt, *tcap, t[i]);
    }
}

int main(int argc, char **argv) {
    int cli_fmt = -1, cli_free = -1, ai = 1;
    long long cli_base = -1;
    char *cli_entry = NULL;
    for (; ai < argc; ai++) {
        const char *a = argv[ai];
        if (a[0] != '-' || !a[1]) break;
        if (!strcmp(a, "-f") && ai + 1 < argc) {
            const char *v = argv[++ai];
            cli_fmt = !strcmp(v, "bin") ? FMT_BIN : !strcmp(v, "pe") ? FMT_PE : FMT_ELF;
        } else if (!strcmp(a, "-b") && ai + 1 < argc) cli_base = strtoll(argv[++ai], 0, 0);
        else if (!strcmp(a, "-e") && ai + 1 < argc) cli_entry = argv[++ai];
        else if (!strcmp(a, "-r")) cli_free = 1;
        else { fprintf(stderr, "unknown option: %s\n", a); return 1; }
    }
    if (ai >= argc) {
        fprintf(stderr, "Usage: %s [-f elf|bin|pe] [-b base] [-e sym] [-r] <source-file>... [output-file]\n", argv[0]);
        return 1;
    }
    int npos = argc - ai;
    const char *out = npos >= 2 ? argv[argc - 1] : "a.out";
    int nsrc = npos >= 2 ? npos - 1 : npos;
    size_t ol = strlen(out);
    fmt = ol >= 4 && !memcmp(out + ol - 4, ".exe", 4) ? FMT_PE : FMT_ELF;

    Token *tokens = NULL;
    int tcnt = 0, tcap = 0;
    for (int i = 0; i < nsrc; i++) {
        printf("Compiling %s...\n", argv[ai + i]);
        if (import_seen(argv[ai + i])) continue;
        import_mark(argv[ai + i]);
        load_tokens(argv[ai + i], &tokens, &tcnt, &tcap);
    }
    PUSH(tokens, tcnt, tcap, tok(TOK_EOF, "", 0, 0));

    Parser p = { tokens, tcnt, 0 };
    adv(&p);
    ASTNode *root = parse_program(&p);

    if (cli_fmt >= 0) fmt = cli_fmt;
    if (cli_base >= 0) load_base = cli_base;
    if (cli_entry) entry_name = cli_entry;
    if (cli_free >= 0) freestanding = cli_free;
    if (raw_mode) { fmt = FMT_BIN; freestanding = 1; }
    if (boot_mode) { fmt = FMT_BIN; freestanding = 1; load_base = 0x100000; }
    if (fmt == FMT_BIN) freestanding = 1;
    is_pe = fmt == FMT_PE;

    generate_code(root);
    if (fmt == FMT_BIN) write_bin(out);
    else if (is_pe) write_pe(out);
    else write_elf(out);

    printf("Generated %s (%s x86-64)\n", out,
           fmt == FMT_BIN ? "flat binary" : is_pe ? "PE32+" : "ELF");
    return 0;
}

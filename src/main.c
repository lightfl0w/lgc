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
    TOK_FOR, TOK_SWITCH, TOK_CASE, TOK_DEFAULT, TOK_STRUCT, TOK_ENUM, TOK_NAKED,
    TOK_DOT, TOK_ARROW,
    TOK_STR,
    TOK_IDENTIFIER, TOK_NUMBER,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH,
    TOK_AMP, TOK_PIPE, TOK_CARET, TOK_TILDE, TOK_SHL, TOK_SHR,
    TOK_LBRACKET, TOK_RBRACKET,
    TOK_ASSIGN, TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_SEMICOLON, TOK_COMMA, TOK_COLON,
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

static const char *KWD[] = { "let", "print", "if", "else", "while", "return", "func", "sizeof", "int", "char", "const", "break", "continue", "extern", "for", "switch", "case", "default", "struct", "enum", "naked" };

static const uint64_t PUNCT_BIT[2] = {
    (1ULL << 33) | (1ULL << 37) | (1ULL << 38) | (1ULL << 40) | (1ULL << 41) | (1ULL << 42) | (1ULL << 43) |
    (1ULL << 44) | (1ULL << 45) | (1ULL << 47) | (1ULL << 58) | (1ULL << 59) |
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
    [';'] = TOK_SEMICOLON, [','] = TOK_COMMA, [':'] = TOK_COLON,
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
        for (int i = 0; i < (int)(sizeof KWD / sizeof *KWD); i++)
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
    if (c == '-' && lx->src[s + 1] == '>') {
        lx->pos = s + 2;
        return tok(TOK_ARROW, &lx->src[s], 2, line);
    }
    if (c == '.') {
        lx->pos = s + 1;
        return tok(TOK_DOT, &lx->src[s], 1, line);
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
    NODE_BNOT, NODE_BREAK, NODE_CONTINUE, NODE_EXTERN_FUNC, NODE_EXTERN_GLOB,
    NODE_FOR, NODE_SWITCH, NODE_CASE, NODE_MEMBER, NODE_STRUCTDEF
} NodeType;
typedef enum { OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_EQ, OP_NE, OP_LT, OP_GT, OP_LE, OP_GE, OP_MOD, OP_AND, OP_OR,
               OP_BOR, OP_BAND, OP_BXOR, OP_SHL, OP_SHR } BinOp;

typedef struct Type { uint8_t kind; int len; uint8_t sz; struct Type *base; struct Field *fields; int nfield; } Type;
typedef struct Field { char *name; Type *ty; int off; } Field;

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
static int ty_size(Type *t) { return t->kind == 2 ? t->len * ty_size(t->base) : t->kind == 3 ? t->len : t->sz; }
static int is_char(Type *t) { return t->kind == 0 && t->sz == 1; }

#define STRUCT_MAX 128
#define FIELD_MAX 1024
static struct { char *name; Type *ty; } STRUCTS[STRUCT_MAX]; static int nstruct;
static Field FIELDPOOL[FIELD_MAX]; static int nfieldpool;
static Type *ty_rec(void) {
    static Type t[256]; static int n;
    if (n >= (int)(sizeof t / sizeof *t)) die("too many structs", 0);
    t[n] = (Type){ 3, 0, 0, NULL, NULL, 0 };
    return &t[n++];
}
static Type *struct_find(const char *name) {
    for (int i = 0; i < nstruct; i++) if (!strcmp(STRUCTS[i].name, name)) return STRUCTS[i].ty;
    return NULL;
}
static Field *struct_field(Type *st, const char *f) {
    for (int i = 0; i < st->nfield; i++) if (!strcmp(st->fields[i].name, f)) return &st->fields[i];
    return NULL;
}

typedef struct ASTNode {
    NodeType type;
    int line;
    union {
        struct { long value; } number;
        struct { char *name; } variable;
        struct { BinOp op; struct ASTNode *left, *right; } binary;
        struct { char *name; Type *ty; struct ASTNode *value; } let;
        struct { struct ASTNode **args; int ncount; } print;
        struct { struct ASTNode **stmts; int count, cap; } block;
        struct { struct ASTNode *cond, *then, *else_; } if_node;
        struct { struct ASTNode *cond, *body; } while_node;
        struct { struct ASTNode *value; } return_node;
        struct { char *name; char **params; Type **ptypes; int pcount; int naked; struct ASTNode *body; } function;
        struct { char *name; struct ASTNode **args; int acount; } call;
        struct { struct ASTNode *value; } unary;
        struct { struct ASTNode *base, *index; } index;
        struct { struct ASTNode *lhs, *rhs; int cop; } assign;
        struct { char *name; int pcount; } extfn;
        struct { char *name; } extgl;
        struct { int off, len; } str;
        struct { struct ASTNode *init, *cond, *inc, *body; } for_node;
        struct { struct ASTNode *expr; struct ASTNode **arms; int narms; } switch_node;
        struct { struct ASTNode *base; char *field; int arrow; } member;
        struct { char *tag; struct ASTNode *body; } structdef;
        struct { long val; int is_default; struct ASTNode *blk; } case_arm;
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
    Type *t;
    if (p->cur.type == TOK_STRUCT) {
        adv(p);
        if (p->cur.type != TOK_IDENTIFIER) die("expected struct tag", p->cur.line);
        t = struct_find(p->cur.text);
        if (!t) die("undefined struct type", p->cur.line);
        adv(p);
    } else {
        if (p->cur.type != TOK_INT && p->cur.type != TOK_CHAR) die("expected type", p->cur.line);
        t = p->cur.type == TOK_CHAR ? &TY_CHAR : &TY_INT;
        adv(p);
    }
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
    for (;;) {
        if (p->cur.type == TOK_LBRACKET) {
            int line = p->cur.line;
            adv(p);
            ASTNode *i = node(NODE_INDEX, line);
            i->data.index.base = n;
            i->data.index.index = parse_expression(p);
            expect(p, TOK_RBRACKET, "expected ']'");
            n = i;
        } else if (p->cur.type == TOK_DOT || p->cur.type == TOK_ARROW) {
            int line = p->cur.line, arrow = p->cur.type == TOK_ARROW;
            adv(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected member name", p->cur.line);
            ASTNode *m = node(NODE_MEMBER, line);
            m->data.member.base = n;
            m->data.member.field = p->cur.text;
            m->data.member.arrow = arrow;
            adv(p);
            n = m;
        } else break;
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
            if (p->cur.type == TOK_INT || p->cur.type == TOK_CHAR || p->cur.type == TOK_STRUCT) ty = parse_type(p);
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
            ASTNode **args = NULL; int na = 0, acap = 0;
            do { PUSH(args, na, acap, parse_expression(p)); }
            while (p->cur.type == TOK_COMMA && (adv(p), 1));
            n->data.print.args = args;
            n->data.print.ncount = na;
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
        case TOK_FOR: {
            adv(p);
            expect(p, TOK_LPAREN, "expected '('");
            ASTNode *n = node(NODE_FOR, t.line);
            if (p->cur.type == TOK_SEMICOLON) { adv(p); n->data.for_node.init = NULL; }
            else n->data.for_node.init = parse_statement(p);
            n->data.for_node.cond = (p->cur.type == TOK_SEMICOLON) ? NULL : parse_expression(p);
            expect(p, TOK_SEMICOLON, "expected ';' in for");
            n->data.for_node.inc = (p->cur.type == TOK_RPAREN) ? NULL : parse_expression(p);
            expect(p, TOK_RPAREN, "expected ')'");
            n->data.for_node.body = parse_statement(p);
            return n;
        }
        case TOK_SWITCH: {
            adv(p);
            expect(p, TOK_LPAREN, "expected '('");
            ASTNode *n = node(NODE_SWITCH, t.line);
            n->data.switch_node.expr = parse_expression(p);
            expect(p, TOK_RPAREN, "expected ')'");
            expect(p, TOK_LBRACE, "expected '{'");
            ASTNode **arms = NULL; int na = 0, acap = 0; ASTNode *cur = NULL;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                if (p->cur.type == TOK_CASE || p->cur.type == TOK_DEFAULT) {
                    cur = node(NODE_CASE, p->cur.line);
                    cur->data.case_arm.blk = node(NODE_BLOCK, p->cur.line);
                    PUSH(arms, na, acap, cur);
                    if (p->cur.type == TOK_CASE) {
                        adv(p);
                        ASTNode *e = parse_expression(p);
                        if (e->type != NODE_NUMBER) die("case value must be a constant", e->line);
                        cur->data.case_arm.val = e->data.number.value;
                    } else { cur->data.case_arm.is_default = 1; adv(p); }
                    expect(p, TOK_COLON, "expected ':'");
                } else {
                    if (!cur) die("statement outside case label", p->cur.line);
                    ASTNode *b = cur->data.case_arm.blk;
                    PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, parse_statement(p));
                }
            }
            expect(p, TOK_RBRACE, "expected '}'");
            n->data.switch_node.arms = arms;
            n->data.switch_node.narms = na;
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
        case TOK_STRUCT: {
            adv(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected struct tag", p->cur.line);
            char *tag = p->cur.text;
            adv(p);
            expect(p, TOK_LBRACE, "expected '{'");
            int base = nfieldpool, nf = 0, off = 0;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                Type *ft = parse_type(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected field name", p->cur.line);
                char *fn = p->cur.text;
                adv(p);
                expect(p, TOK_SEMICOLON, "expected ';' after field");
                int fsz = ty_size(ft);
                int al = fsz >= 8 ? 8 : (fsz >= 4 ? 4 : (fsz >= 2 ? 2 : 1));
                off = (off + al - 1) & ~(al - 1);
                if (nfieldpool >= FIELD_MAX) die("too many struct fields", p->cur.line);
                FIELDPOOL[nfieldpool++] = (Field){ fn, ft, off };
                off += fsz; nf++;
            }
            expect(p, TOK_RBRACE, "expected '}'");
            expect(p, TOK_SEMICOLON, "expected ';' after struct");
            Type *st = ty_rec();
            st->fields = &FIELDPOOL[base];
            st->nfield = nf;
            st->len = (off + 7) & ~7;
            if (nstruct >= STRUCT_MAX) die("too many structs", t.line);
            STRUCTS[nstruct].name = tag; STRUCTS[nstruct].ty = st; nstruct++;
            return node(NODE_BLOCK, t.line);
        }
        case TOK_ENUM: {
            adv(p);
            if (p->cur.type == TOK_IDENTIFIER) adv(p);
            expect(p, TOK_LBRACE, "expected '{'");
            long next = 0;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                if (p->cur.type != TOK_IDENTIFIER) die("expected enum name", p->cur.line);
                char *nm = p->cur.text;
                adv(p);
                long val = next;
                if (p->cur.type == TOK_ASSIGN) {
                    adv(p);
                    ASTNode *e = parse_expression(p);
                    if (e->type != NODE_NUMBER) die("enum value must be a constant", e->line);
                    val = e->data.number.value;
                }
                if (p->cur.type == TOK_COMMA) adv(p);
                if (nconst >= (int)(sizeof CONSTS / sizeof *CONSTS)) die("too many consts", p->cur.line);
                CONSTS[nconst].name = nm; CONSTS[nconst].value = val; nconst++;
                next = val + 1;
            }
            expect(p, TOK_RBRACE, "expected '}'");
            if (p->cur.type == TOK_SEMICOLON) adv(p);
            return node(NODE_BLOCK, t.line);
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

static ASTNode *parse_function(Parser *p, int naked) {
    int line = p->cur.line;
    adv(p);
    if (p->cur.type != TOK_IDENTIFIER) die("expected func name", p->cur.line);
    ASTNode *f = node(NODE_FUNCTION, line);
    f->data.function.name = p->cur.text;
    f->data.function.naked = naked;
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
static int printstrlab;
static int cur_naked;

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
        int naked = 0;
        if (p->cur.type == TOK_NAKED) { naked = 1; adv(p); }
        if (naked && p->cur.type != TOK_FUNC) die("naked must precede func", p->cur.line);
        PUSH(root->data.block.stmts, root->data.block.count, root->data.block.cap,
             p->cur.type == TOK_FUNC ? parse_function(p, naked) : parse_statement(p));
    }
    return root;
}

static uint8_t code[262144];
static int clen, entry, is_pe;
static int lab_pos[8192], nlab = 1;
static struct { int pos, lab, g; } PATCH[8192];
static uint8_t p_sz[8192];
static int p_base[8192];
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
    if (bin_fmt && !raw_mode && v >= 0 && v <= 127) { EMIT(0xB8); emit_imm(v, 4); return; }
    if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x58);
    else if (v >= 0 && v <= 0xFFFFFFFFLL) { EMIT(0xB8); emit_imm(v, 4); }
    else if (v >= -2147483648LL && v <= -1) { EMIT(0x48, 0xC7, 0xC0); emit_imm(v, 4); }
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
    p_sz[npatch] = 4;
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

static void greg_load_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x8B, (uint8_t)(0xC0 | (r & 7))); }
static void greg_store_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x89, (uint8_t)(0xC0 | (r & 7))); }
static void greg_load_rcx(int r) { EMIT((uint8_t)(0x48 | ((r >= 8) << 2)), 0x89, (uint8_t)(0xC0 | ((r & 7) << 3) | 1)); }
static void greg_zero(int r) { EMIT((uint8_t)(0x40 | ((r >= 8) << 2) | (r >= 8)), 0x31, (uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7))); }

static void apply_patches(void) {
    for (int i = 0; i < npatch; i++) {
        int p = PATCH[i].pos, t = 0, sz = p_sz[i];
        int64_t rel;
        if (PATCH[i].g == 0) t = lab_pos[PATCH[i].lab];
        else if (PATCH[i].g == 1) t = lab_pos[litlab] + PATCH[i].lab;
        else if (PATCH[i].g == 3) t = lab_pos[PATCH[i].lab];
        if (PATCH[i].g == 3) rel = t - lab_pos[p_base[i]];
        else if (PATCH[i].g < 2) rel = t - (p + sz);
        else if (is_pe)
            rel = (int64_t)pcb + ((clen + 15) & ~15) + 176 + PATCH[i].lab - (pcb + p + 4);
        else {
            int64_t hdr = 64 + 56;
            int64_t dva = 0x400000 + hdr + clen;
            rel = dva + PATCH[i].lab - (0x400000 + hdr + p + 4);
        }
        if (sz == 1) code[p] = (uint8_t)(int8_t)rel;
        else *(int32_t *)(code + p) = (int32_t)rel;
    }
}

static uint8_t sh_del[262144], sh_new[262144];
static int sh_map[262144 + 1];
static int sh_flag[8192], sh_kind[8192], sh_patch[8192], sh_nc;

static void shrink_relayout(void) {
    sh_nc = 0;
    for (int i = 0; i < npatch; i++) {
        if (PATCH[i].g != 0) continue;
        int p = PATCH[i].pos;
        sh_flag[i] = 0;
        if (code[p - 1] == 0xE9) { sh_patch[sh_nc] = i; sh_kind[sh_nc] = 0; sh_nc++; }
        else if (code[p - 2] == 0x0F && (code[p - 1] & 0xF0) == 0x80) { sh_patch[sh_nc] = i; sh_kind[sh_nc] = 1; sh_nc++; }
    }
    int oldlen = clen;
    for (int iter = 0; iter < 64; iter++) {
        memset(sh_del, 0, oldlen);
        for (int k = 0; k < sh_nc; k++) {
            if (!sh_flag[sh_patch[k]]) continue;
            int p = PATCH[sh_patch[k]].pos;
            if (sh_kind[k] == 1) sh_del[p - 1] = 1;
            sh_del[p + 1] = sh_del[p + 2] = sh_del[p + 3] = 1;
        }
        int c = 0;
        for (int x = 0; x <= oldlen; x++) { sh_map[x] = c; if (x < oldlen && !sh_del[x]) c++; }
        int changed = 0;
        for (int k = 0; k < sh_nc; k++) {
            int i = sh_patch[k]; if (sh_flag[i]) continue;
            int p = PATCH[i].pos;
            int rel = sh_map[lab_pos[PATCH[i].lab]] - (sh_map[p] + 1);
            if (rel >= -128 && rel <= 127) { sh_flag[i] = 1; changed = 1; }
        }
        if (!changed) break;
    }
    for (int k = 0; k < sh_nc; k++) {
        int i = sh_patch[k]; if (!sh_flag[i]) continue;
        int p = PATCH[i].pos;
        if (sh_kind[k] == 0) code[p - 1] = 0xEB;
        else code[p - 2] = (uint8_t)((code[p - 1] & 0x0F) | 0x70);
    }
    int w = 0;
    for (int x = 0; x < oldlen; x++) if (!sh_del[x]) sh_new[w++] = code[x];
    memcpy(code, sh_new, w);
    for (int l = 0; l < nlab; l++) lab_pos[l] = sh_map[lab_pos[l]];
    entry = sh_map[entry];
    for (int i = 0; i < npatch; i++) {
        PATCH[i].pos = sh_map[PATCH[i].pos];
        if (PATCH[i].g == 0 && sh_flag[i]) p_sz[i] = 1;
    }
    for (int i = 0; i < niat; i++) IAT_PATCH[i] = (sh_map[IAT_PATCH[i] >> 2] << 2) | (IAT_PATCH[i] & 3);
    clen = w;
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
    EMIT(0x66,0xBA,0xF8,0x03);
    int oloop = new_label();
    put_label(oloop);
    EMIT(0x48,0x39,0xEE);
    int onl = new_label();
    emit_jcc(0x83, onl);
    EMIT(0x8A,0x06);
    EMIT(0xEE);
    EMIT(0x48,0xFF,0xC6);
    emit_jmp(oloop);
    put_label(onl);
    EMIT(0xB0,0x0A);
    EMIT(0xEE);
    EMIT(0xC9,0xC3);
}

static void emit_print_str_elf(void) {
    EMIT(0x48,0x89,0xC6);
    EMIT(0x48,0x89,0xF2);
    int scan = new_label();
    put_label(scan);
    EMIT(0x0F,0xB6,0x02);
    EMIT(0x84,0xC0);
    int done = new_label();
    emit_jcc(0x84, done);
    EMIT(0x48,0xFF,0xC2);
    emit_jmp(scan);
    put_label(done);
    EMIT(0x48,0x29,0xF2);
    EMIT(0x6A,0x01,0x58);
    EMIT(0x6A,0x01,0x5F);
    EMIT(0x0F,0x05);
    EMIT(0xC3);
}

static void emit_print_str_pe(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x50);
    EMIT(0x48,0x89,0xC6);
    EMIT(0x48,0x89,0xF2);
    int scan = new_label();
    put_label(scan);
    EMIT(0x0F,0xB6,0x02);
    EMIT(0x84,0xC0);
    int done = new_label();
    emit_jcc(0x84, done);
    EMIT(0x48,0xFF,0xC2);
    emit_jmp(scan);
    put_label(done);
    EMIT(0x48,0x29,0xF2);
    EMIT(0x48,0x89,0xD7);
    EMIT(0x6A,0xF5,0x59);
    emit_call_iat(0);
    EMIT(0x48,0x89,0xC1);
    EMIT(0x48,0x89,0xF2);
    EMIT(0x49,0x89,0xF8);
    EMIT(0x4C,0x8D,0x4C,0x24,0x28);
    EMIT(0x48,0xC7,0x44,0x24,0x20); emit_imm(0,4);
    emit_call_iat(1);
    EMIT(0xC9,0xC3);
}

static void emit_print_str_bare(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x20);
    EMIT(0x48,0x89,0xC6);
    EMIT(0x66,0xBA,0xF8,0x03);
    int oloop = new_label();
    put_label(oloop);
    EMIT(0x0F,0xB6,0x06);
    EMIT(0x84,0xC0);
    int done = new_label();
    emit_jcc(0x84, done);
    EMIT(0xEE);
    EMIT(0x48,0xFF,0xC6);
    emit_jmp(oloop);
    put_label(done);
    EMIT(0xB0,0x0A);
    EMIT(0xEE);
    EMIT(0xC9,0xC3);
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

static Type *ty_of_expr(ASTNode *n);
static Type *struct_of(ASTNode *b, int arrow) {
    Type *bt = ty_of_expr(b);
    if (arrow) { if (bt->kind != 1) die("-> applied to non-pointer", b->line); bt = bt->base; }
    if (!bt || bt->kind != 3) die("member access on non-struct", b->line);
    return bt;
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
        case NODE_MEMBER: {
            Type *st = struct_of(n->data.member.base, n->data.member.arrow);
            Field *f = struct_field(st, n->data.member.field);
            if (!f) die("no such field", n->line);
            return f->ty;
        }
        default:          return &TY_INT;
    }
}

static int is_str_ty(Type *t) {
    return (t->kind == 1 || t->kind == 2) && is_char(t->base);
}
static int is_string_arg(ASTNode *e) { return is_str_ty(ty_of_expr(e)); }

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
        case NODE_MEMBER: {
            ASTNode *b = n->data.member.base;
            int arrow = n->data.member.arrow;
            Type *st = struct_of(b, arrow);
            Field *f = struct_field(st, n->data.member.field);
            if (!f) die("no such field", n->line);
            if (arrow) gen_expr(b); else gen_addr(b);
            if (f->off) {
                if (f->off <= 127) EMIT(0x48, 0x83, 0xC0, (uint8_t)f->off);
                else { EMIT(0x48, 0x05); emit_imm(f->off, 4); }
            }
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
        case NODE_MEMBER: {
            Type *ft = ty_of_expr(n);
            gen_addr(n);
            if (ft->kind == 2 || ft->kind == 3) { }
            else if (is_char(ft)) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        }
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
                    case OP_ADD: EMIT((uint8_t)(0x48 | (r >= 8)), 0x01, (uint8_t)(0xC0 | (r & 7))); break;
                    case OP_SUB: EMIT((uint8_t)(0x48 | (r >= 8)), 0x29, (uint8_t)(0xC0 | (r & 7))); break;
                    case OP_MUL: EMIT(0x4C, 0x0F, 0xAF, (uint8_t)(0xC0 | ((r & 7) << 3))); break;
                    default: {
                        greg_load_rcx(r);
                        greg_store_rax(r);
                        EMIT(0x48, 0x89, 0xC8);
                        EMIT(0x48, 0x99);
                        EMIT((uint8_t)(0x48 | (r >= 8)), 0xF7, (uint8_t)(0xC0 | 0x38 | (r & 7)));
                        if (cop == OP_MOD) EMIT(0x48, 0x89, 0xD0);
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
            EMIT(0x48, 0x85, 0xC0);
            EMIT(0x0F, 0x94, 0xC0);
            EMIT(0x0F, 0xB6, 0xC0);
            break;
        case NODE_BNOT:
            gen_expr(n->data.unary.value);
            EMIT(0x48, 0xF7, 0xD0);
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
                        if (bin_fmt && !raw_mode && v >= 0 && v <= 127) { EMIT(0xB9); emit_imm(v, 4); }
                        else if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x59);
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
                if (!strcmp(nm, "lgdt")) EMIT(0x0F, 0x01, 0x10);
                else if (!strcmp(nm, "lidt")) EMIT(0x0F, 0x01, 0x18);
                else EMIT(0x0F, 0x22, 0xD8);
                break;
            }
            if (!strcmp(nm, "addr") && fn_find(nm) < 0) {
                if (ac != 1 || n->data.call.args[0]->type != NODE_VARIABLE)
                    die("addr(funcname)", n->line);
                int f = fn_find(n->data.call.args[0]->data.variable.name);
                if (f < 0) die("addr: unknown function", n->line);
                EMIT(0x48, 0x8D, 0x05);
                emit_patch(0, FNS[f].lab);
                break;
            }
            if (!strcmp(nm, "ld32") && fn_find(nm) < 0) {
                if (ac != 1) die("ld32(addr)", n->line);
                gen_expr(n->data.call.args[0]);
                EMIT(0x8B, 0x00);
                break;
            }
            if (!strcmp(nm, "st32") && fn_find(nm) < 0) {
                if (ac != 2) die("st32(addr, val)", n->line);
                gen_expr(n->data.call.args[1]);
                EMIT(0x50);
                gen_expr(n->data.call.args[0]);
                EMIT(0x59);
                EMIT(0x89, 0x08);
                break;
            }
            if (!strcmp(nm, "inb") || !strcmp(nm, "inl")) {
                if (ac != 1) die("inb(port)", n->line);
                ASTNode *a = n->data.call.args[0];
                if (a->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(a->data.number.value, 2); }
                else { gen_expr(a); EMIT(0x66, 0x89, 0xC2); }
                if (nm[2] == 'l') EMIT(0xED);
                else { EMIT(0xEC); EMIT(0x0F, 0xB6, 0xC0); }
                break;
            }
            if (!strcmp(nm, "outb") || !strcmp(nm, "outl")) {
                if (ac != 2) die("outb(port, value)", n->line);
                ASTNode *pa = n->data.call.args[0];
                gen_expr(n->data.call.args[1]);
                EMIT(0x50);
                if (pa->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(pa->data.number.value, 2); }
                else { gen_expr(pa); EMIT(0x66, 0x89, 0xC2); }
                EMIT(0x58);
                EMIT(nm[3] == 'l' ? 0xEF : 0xEE);
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
                    EMIT(0xB9);
                    int esz = ty_size(e);
                    int cnt = (e->kind == 3 && esz > 0) ? ty_size(n->data.let.ty) / esz : (is_char(e) ? ty_size(n->data.let.ty) : ty_size(n->data.let.ty) / 8);
                    emit_imm(cnt, 4);
                    if (is_char(e)) EMIT(0xF3, 0xAA); else EMIT(0xF3, 0x48, 0xAB);
                }
            } else if (n->data.let.ty->kind == 3) {
                if (n->data.let.value) die("cannot initialize struct in place", n->line);
            } else {
                if (!n->data.let.value) die("missing initializer", n->line);
                if (is_char(n->data.let.ty)) { EMIT(0x88); rbp_disp(0, l->off); }
                else { EMIT(0x48, 0x89); rbp_disp(0, l->off); }
            }
            break;
        }
        case NODE_PRINT:
            if (freestanding && !boot_mode) die("print is unavailable in freestanding mode", n->line);
            for (int i = 0; i < n->data.print.ncount; i++) {
                ASTNode *e = n->data.print.args[i];
                gen_expr(e);
                EMIT(0xE8);
                emit_patch(0, is_string_arg(e) ? printstrlab : printlab);
            }
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
        case NODE_FOR: {
            if (nloop >= 64) die("loops too deep", n->line);
            int sn = nloc, so = cur_off;
            int lab_body = new_label(), lab_cont = new_label(), lab_test = new_label(), lab_end = new_label();
            if (n->data.for_node.init) gen_stmt(n->data.for_node.init);
            brk_lab[nloop] = lab_end; cont_lab[nloop] = lab_cont; nloop++;
            emit_jmp(lab_test);
            put_label(lab_body);
            gen_stmt(n->data.for_node.body);
            put_label(lab_cont);
            if (n->data.for_node.inc) gen_expr(n->data.for_node.inc);
            put_label(lab_test);
            if (n->data.for_node.cond) { emit_jcc(gen_cond(n->data.for_node.cond), lab_end); emit_jmp(lab_body); }
            else emit_jmp(lab_body);
            put_label(lab_end);
            nloop--;
            nloc = sn; cur_off = so;
            break;
        }
        case NODE_SWITCH: {
            ASTNode **arms = n->data.switch_node.arms;
            int na = n->data.switch_node.narms;
            if (nloop >= 64) die("nesting too deep", n->line);
            int sn = nloc, so = cur_off;
            int lab_end = new_label(), def_lab = lab_end;
            int alab[na > 0 ? na : 1];
            int nc = 0; long lo = 0, hi = 0;
            for (int k = 0; k < na; k++) {
                alab[k] = new_label();
                if (arms[k]->data.case_arm.is_default) def_lab = alab[k];
                else { long v = arms[k]->data.case_arm.val; if (!nc) { lo = hi = v; } else { if (v < lo) lo = v; if (v > hi) hi = v; } nc++; }
            }
            long span = hi - lo;
            int use_table = nc >= 4 && span <= 512 && span <= 4 * nc;
            brk_lab[nloop] = lab_end; cont_lab[nloop] = lab_end; nloop++;
            if (use_table) {
                int tbl = new_label();
                gen_expr(n->data.switch_node.expr);
                EMIT(0x48, 0x89, 0xC7);
                EMIT(0x48, 0x81, 0xEF); emit_imm(lo, 4);
                EMIT(0x48, 0x81, 0xFF); emit_imm(span, 4);
                emit_jcc(0x87, def_lab);
                EMIT(0x48, 0x8D, 0x15); emit_patch(0, tbl);
                EMIT(0x48, 0x63, 0x04, 0xBA);
                EMIT(0x48, 0x01, 0xD0);
                EMIT(0xFF, 0xE0);
                for (int k = 0; k < na; k++) {
                    put_label(alab[k]);
                    ASTNode *b = arms[k]->data.case_arm.blk;
                    for (int i = 0; i < b->data.block.count; i++) gen_stmt(b->data.block.stmts[i]);
                }
                emit_jmp(lab_end);
                put_label(tbl);
                for (long i = 0; i <= span; i++) {
                    int t = def_lab;
                    for (int k = 0; k < na; k++)
                        if (!arms[k]->data.case_arm.is_default && arms[k]->data.case_arm.val == lo + i) { t = alab[k]; break; }
                    int idx = npatch;
                    emit_patch(3, t);
                    p_base[idx] = tbl;
                }
            } else {
                gen_expr(n->data.switch_node.expr);
                for (int k = 0; k < na; k++) {
                    if (arms[k]->data.case_arm.is_default) continue;
                    emit_cmp_rax_imm(arms[k]->data.case_arm.val);
                    emit_jcc(0x84, alab[k]);
                }
                emit_jmp(def_lab);
                for (int k = 0; k < na; k++) {
                    put_label(alab[k]);
                    ASTNode *b = arms[k]->data.case_arm.blk;
                    for (int i = 0; i < b->data.block.count; i++) gen_stmt(b->data.block.stmts[i]);
                }
            }
            nloop--;
            put_label(lab_end);
            nloc = sn; cur_off = so;
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
            if (cur_naked) EMIT(0xC3);
            else EMIT(0xC9, 0xC3);
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
    if (n->type == NODE_FOR) return (n->data.for_node.init && needs_frame(n->data.for_node.init)) || needs_frame(n->data.for_node.body);
    if (n->type == NODE_SWITCH) {
        for (int i = 0; i < n->data.switch_node.narms; i++)
            if (needs_frame(n->data.switch_node.arms[i]->data.case_arm.blk)) return 1;
        return 0;
    }
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
        case NODE_PRINT:
            for (int i = 0; i < n->data.print.ncount; i++) scan_node(n->data.print.args[i], w);
            break;
        case NODE_RETURN: scan_node(n->data.return_node.value, w); break;
        case NODE_INDEX:
            scan_node(n->data.index.base, w);
            scan_node(n->data.index.index, w);
            break;
        case NODE_MEMBER:
            scan_node(n->data.member.base, w);
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
        case NODE_FOR:
            scan_node(n->data.for_node.init, w);
            scan_node(n->data.for_node.cond, w * 8);
            scan_node(n->data.for_node.inc, w * 8);
            scan_node(n->data.for_node.body, w * 8);
            break;
        case NODE_SWITCH:
            scan_node(n->data.switch_node.expr, w);
            for (int i = 0; i < n->data.switch_node.narms; i++)
                scan_node(n->data.switch_node.arms[i]->data.case_arm.blk, w);
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
        EMIT(0xE8); emit_patch(0, FNS[mi].lab);
        if (freestanding) EMIT(0xEB, 0xFE);
        else if (is_pe) {
            EMIT(0x48, 0x89, 0xC1);
            emit_call_iat(2);
        } else {
            EMIT(0x48, 0x89, 0xC7);
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
    if (!freestanding) {
        printlab = new_label(); put_label(printlab);
        if (is_pe) emit_print_pe(); else emit_print_elf();
        printstrlab = new_label(); put_label(printstrlab);
        if (is_pe) emit_print_str_pe(); else emit_print_str_elf();
    }
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

    if (!freestanding) pick_glob_regs(root);

    if (bin_fmt) { entry = clen; emit_entry(root); }

    if (boot_mode) {
        printlab = new_label();
        put_label(printlab);
        emit_print_bare();
        printstrlab = new_label();
        put_label(printstrlab);
        emit_print_str_bare();
    }

    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        put_label(FNS[fn_find(f->data.function.name)].lab);
        int pp = -1;
        cur_naked = f->data.function.naked;
        if (!cur_naked) pp = emit_prologue();
        nloc = 0; cur_off = 0; frame_min = 0;
        if (f->data.function.pcount > 0 && !cur_naked) {
            EMIT(0x48, 0x89, 0xF8);
            int off = loc_add(f->data.function.params[0], &TY_INT)->off;
            EMIT(0x48, 0x89); rbp_disp(0, off);
        }
        if (f->data.function.pcount > 0 && !cur_naked)
            for (int k = 1; k < f->data.function.pcount; k++) {
                int off = loc_add(f->data.function.params[k], &TY_INT)->off;
                EMIT(0x48, 0x8B); rbp_disp(0, 16 + 8 * (k - 1));
                EMIT(0x48, 0x89); rbp_disp(0, off);
            }
        gen_stmt(f->data.function.body);
        if (!cur_naked) { EMIT(0xC9, 0xC3); patch_prologue(pp); }
        cur_naked = 0;
    }

    if (!bin_fmt) { entry = clen; emit_entry(root); }

    put_label(litlab);
    if (nlit) { memcpy(code + clen, LIT, nlit); clen += nlit; }
    shrink_relayout();
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

static ASTNode *mk_num(long v, int line) {
    ASTNode *n = node(NODE_NUMBER, line);
    n->data.number.value = v;
    return n;
}

static ASTNode *mk_var(const char *name, int line) {
    ASTNode *n = node(NODE_VARIABLE, line);
    n->data.variable.name = (char *)name;
    return n;
}

static ASTNode *mk_let(const char *name, ASTNode *val, int line) {
    ASTNode *n = node(NODE_LET, line);
    n->data.let.name = (char *)name;
    n->data.let.ty = &TY_INT;
    n->data.let.value = val;
    return n;
}

static int has_side_effect(ASTNode *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_ASSIGN:
        case NODE_CALL:
            return 1;
        case NODE_BINARY:
            return has_side_effect(n->data.binary.left) || has_side_effect(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT: case NODE_ADDR: case NODE_DEREF:
            return has_side_effect(n->data.unary.value);
        case NODE_INDEX:
            return has_side_effect(n->data.index.base) || has_side_effect(n->data.index.index);
        case NODE_MEMBER:
            return has_side_effect(n->data.member.base);
        default:
            return 0;
    }
}

static int is_spec_pure(ASTNode *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_NUMBER:
        case NODE_VARIABLE:
            return 1;
        case NODE_BINARY:
            if (n->data.binary.op == OP_DIV || n->data.binary.op == OP_MOD) return 0;
            return is_spec_pure(n->data.binary.left) && is_spec_pure(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT:
            return is_spec_pure(n->data.unary.value);
        default:
            return 0;
    }
}

static int ast_equal(ASTNode *a, ASTNode *b) {
    if (a == b) return 1;
    if (!a || !b || a->type != b->type) return 0;
    switch (a->type) {
        case NODE_NUMBER: return a->data.number.value == b->data.number.value;
        case NODE_VARIABLE: return !strcmp(a->data.variable.name, b->data.variable.name);
        case NODE_BINARY:
            return a->data.binary.op == b->data.binary.op &&
                   ast_equal(a->data.binary.left, b->data.binary.left) &&
                   ast_equal(a->data.binary.right, b->data.binary.right);
        case NODE_NOT: case NODE_BNOT:
            return ast_equal(a->data.unary.value, b->data.unary.value);
        default: return 0;
    }
}

static ASTNode *fold_binary(ASTNode *n) {
    BinOp op = n->data.binary.op;
    ASTNode *l = n->data.binary.left, *r = n->data.binary.right;
    int lc = l->type == NODE_NUMBER, rc = r->type == NODE_NUMBER;
    long lv = lc ? l->data.number.value : 0, rv = rc ? r->data.number.value : 0;
    if (lc && rc) return mkbin(op, l, r, n->line);
    switch (op) {
        case OP_ADD:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case OP_SUB:
            if (rc && rv == 0) return l;
            break;
        case OP_MUL:
            if (lc && lv == 0) return mk_num(0, n->line);
            if (rc && rv == 0) return mk_num(0, n->line);
            if (lc && lv == 1) return r;
            if (rc && rv == 1) return l;
            if (rc && rv > 0 && (rv & (rv - 1)) == 0)
                return mkbin(OP_SHL, l, mk_num(__builtin_ctzll((unsigned long long)rv), n->line), n->line);
            if (lc && lv > 0 && (lv & (lv - 1)) == 0)
                return mkbin(OP_SHL, r, mk_num(__builtin_ctzll((unsigned long long)lv), n->line), n->line);
            break;
        case OP_DIV:
            if (rc && rv == 1) return l;
            break;
        case OP_MOD:
            if (rc && rv == 1) return mk_num(0, n->line);
            break;
        case OP_BOR:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case OP_BAND:
            if (lc && lv == -1) return r;
            if (rc && rv == -1) return l;
            break;
        case OP_BXOR:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case OP_SHL:
        case OP_SHR:
            if (rc && rv == 0) return l;
            break;
        default:
            break;
    }
    if (ast_equal(l, r) && is_spec_pure(l)) {
        if (op == OP_BAND || op == OP_BOR) return l;
        if (op == OP_BXOR || op == OP_SUB) return mk_num(0, n->line);
        if (op == OP_EQ || op == OP_LE || op == OP_GE) return mk_num(1, n->line);
        if (op == OP_NE || op == OP_LT || op == OP_GT) return mk_num(0, n->line);
    }
    return n;
}

static ASTNode *opt_fold_expr(ASTNode *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_BINARY:
            n->data.binary.left = opt_fold_expr(n->data.binary.left);
            n->data.binary.right = opt_fold_expr(n->data.binary.right);
            return fold_binary(n);
        case NODE_NOT:
            n->data.unary.value = opt_fold_expr(n->data.unary.value);
            if (n->data.unary.value->type == NODE_NUMBER)
                return mk_num(!n->data.unary.value->data.number.value, n->line);
            return n;
        case NODE_BNOT:
            n->data.unary.value = opt_fold_expr(n->data.unary.value);
            if (n->data.unary.value->type == NODE_NUMBER)
                return mk_num(~n->data.unary.value->data.number.value, n->line);
            return n;
        case NODE_ADDR: case NODE_DEREF:
            n->data.unary.value = opt_fold_expr(n->data.unary.value);
            return n;
        case NODE_INDEX:
            n->data.index.base = opt_fold_expr(n->data.index.base);
            n->data.index.index = opt_fold_expr(n->data.index.index);
            return n;
        case NODE_MEMBER:
            n->data.member.base = opt_fold_expr(n->data.member.base);
            return n;
        case NODE_ASSIGN:
            n->data.assign.lhs = opt_fold_expr(n->data.assign.lhs);
            n->data.assign.rhs = opt_fold_expr(n->data.assign.rhs);
            return n;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++)
                n->data.call.args[i] = opt_fold_expr(n->data.call.args[i]);
            return n;
        default:
            return n;
    }
}

static void opt_fold_block(ASTNode *b);
static void opt_fold_stmt(ASTNode **slot);

static void opt_fold_stmt(ASTNode **slot) {
    ASTNode *n = *slot;
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            if (n->data.let.value) n->data.let.value = opt_fold_expr(n->data.let.value);
            break;
        case NODE_PRINT:
            for (int i = 0; i < n->data.print.ncount; i++)
                n->data.print.args[i] = opt_fold_expr(n->data.print.args[i]);
            break;
        case NODE_RETURN:
            n->data.return_node.value = opt_fold_expr(n->data.return_node.value);
            break;
        case NODE_IF:
            n->data.if_node.cond = opt_fold_expr(n->data.if_node.cond);
            opt_fold_stmt(&n->data.if_node.then);
            opt_fold_stmt(&n->data.if_node.else_);
            break;
        case NODE_WHILE:
            n->data.while_node.cond = opt_fold_expr(n->data.while_node.cond);
            opt_fold_stmt(&n->data.while_node.body);
            break;
        case NODE_FOR:
            if (n->data.for_node.init) opt_fold_stmt(&n->data.for_node.init);
            if (n->data.for_node.cond) n->data.for_node.cond = opt_fold_expr(n->data.for_node.cond);
            if (n->data.for_node.inc) n->data.for_node.inc = opt_fold_expr(n->data.for_node.inc);
            opt_fold_stmt(&n->data.for_node.body);
            break;
        case NODE_SWITCH:
            n->data.switch_node.expr = opt_fold_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++)
                opt_fold_block(n->data.switch_node.arms[i]->data.case_arm.blk);
            break;
        case NODE_BLOCK:
            opt_fold_block(n);
            break;
        case NODE_FUNCTION:
            opt_fold_block(n->data.function.body);
            break;
        case NODE_EXTERN_FUNC: case NODE_EXTERN_GLOB:
            break;
        default:
            *slot = opt_fold_expr(n);
            break;
    }
}

static void opt_fold_block(ASTNode *b) {
    if (!b) return;
    for (int i = 0; i < b->data.block.count; i++)
        opt_fold_stmt(&b->data.block.stmts[i]);
}

#define OSC_CAP 65536
static struct { char *name; ASTNode *let; } OSC[OSC_CAP];
static int osc_n;
static void osc_push(void) {
    if (osc_n + 1 >= OSC_CAP) die("scope too deep", 0);
    OSC[osc_n].name = NULL; OSC[osc_n].let = NULL; osc_n++;
}
static void osc_pop(void) {
    while (osc_n > 0 && OSC[osc_n - 1].let) osc_n--;
    if (osc_n > 0) osc_n--;
}
static void osc_add(char *name, ASTNode *let) {
    if (osc_n >= OSC_CAP) die("scope too deep", 0);
    OSC[osc_n].name = name; OSC[osc_n].let = let; osc_n++;
}
static ASTNode *osc_find(const char *name) {
    for (int i = osc_n - 1; i >= 0; i--) {
        if (!OSC[i].let) continue;
        if (!strcmp(OSC[i].name, name)) return OSC[i].let;
    }
    return NULL;
}

#define OIDX(n) ((int)((n) - NODE_ARENA))
static struct { signed char kind; unsigned char flags; long value; ASTNode *src; } OI[NODE_CAP];

static char *GNAME[256]; static int gn;
static long GVAL[256];
static unsigned char GCONST[256], GASS[256], GADDR[256];
static int gidx(const char *name) {
    for (int i = 0; i < gn; i++) if (!strcmp(GNAME[i], name)) return i;
    return -1;
}

static void analyze_expr(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_VARIABLE: break;
        case NODE_BINARY:
            analyze_expr(n->data.binary.left);
            analyze_expr(n->data.binary.right);
            break;
        case NODE_ASSIGN:
            if (n->data.assign.lhs->type == NODE_VARIABLE) {
                ASTNode *L = osc_find(n->data.assign.lhs->data.variable.name);
                if (L) OI[OIDX(L)].flags |= 1;
                else { int g = gidx(n->data.assign.lhs->data.variable.name); if (g >= 0) GASS[g] = 1; }
            }
            analyze_expr(n->data.assign.lhs);
            analyze_expr(n->data.assign.rhs);
            break;
        case NODE_ADDR:
            if (n->data.unary.value->type == NODE_VARIABLE) {
                ASTNode *L = osc_find(n->data.unary.value->data.variable.name);
                if (L) OI[OIDX(L)].flags |= 2;
                else { int g = gidx(n->data.unary.value->data.variable.name); if (g >= 0) GADDR[g] = 1; }
            } else analyze_expr(n->data.unary.value);
            break;
        case NODE_NOT: case NODE_BNOT: case NODE_DEREF:
            analyze_expr(n->data.unary.value);
            break;
        case NODE_INDEX:
            analyze_expr(n->data.index.base);
            analyze_expr(n->data.index.index);
            break;
        case NODE_MEMBER:
            analyze_expr(n->data.member.base);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) analyze_expr(n->data.call.args[i]);
            break;
        default: break;
    }
}

static void analyze_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            analyze_expr(n->data.let.value);
            if (n->data.let.value && n->data.let.value->type == NODE_NUMBER) {
                OI[OIDX(n)].kind = 1; OI[OIDX(n)].value = n->data.let.value->data.number.value;
            } else if (n->data.let.value && n->data.let.value->type == NODE_VARIABLE) {
                ASTNode *SL = osc_find(n->data.let.value->data.variable.name);
                if (SL) { OI[OIDX(n)].kind = 2; OI[OIDX(n)].src = SL; }
            }
            osc_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            osc_push();
            for (int i = 0; i < n->data.block.count; i++) analyze_stmt(n->data.block.stmts[i]);
            osc_pop();
            break;
        case NODE_IF:
            analyze_expr(n->data.if_node.cond);
            osc_push(); analyze_stmt(n->data.if_node.then); osc_pop();
            osc_push(); analyze_stmt(n->data.if_node.else_); osc_pop();
            break;
        case NODE_WHILE:
            analyze_expr(n->data.while_node.cond);
            osc_push(); analyze_stmt(n->data.while_node.body); osc_pop();
            break;
        case NODE_FOR:
            osc_push();
            analyze_stmt(n->data.for_node.init);
            analyze_expr(n->data.for_node.cond);
            analyze_expr(n->data.for_node.inc);
            analyze_stmt(n->data.for_node.body);
            osc_pop();
            break;
        case NODE_SWITCH:
            analyze_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                osc_push(); analyze_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); osc_pop();
            }
            break;
        case NODE_RETURN: analyze_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) analyze_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: osc_n = 0; analyze_stmt(n->data.function.body); break;
        default: analyze_expr(n); break;
    }
}

static void analyze_program(ASTNode *root) {
    gn = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        GNAME[gn] = n->data.let.name;
        if (n->data.let.value && n->data.let.value->type == NODE_NUMBER) {
            GVAL[gn] = n->data.let.value->data.number.value; GCONST[gn] = 1;
        } else GCONST[gn] = 0;
        GASS[gn] = 0; GADDR[gn] = 0;
        gn++;
    }
    osc_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) analyze_expr(n->data.let.value);
        else { osc_n = 0; analyze_stmt(n); }
    }
    osc_n = 0;
}

static ASTNode *prop_expr(ASTNode *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_VARIABLE: {
            ASTNode *L = osc_find(n->data.variable.name);
            if (L && !(OI[OIDX(L)].flags & 3) && OI[OIDX(L)].kind) {
                ASTNode *cur = L;
                while (cur && OI[OIDX(cur)].kind == 2 && !(OI[OIDX(cur)].flags & 3) && OI[OIDX(cur)].src)
                    cur = OI[OIDX(cur)].src;
                if (cur && OI[OIDX(cur)].kind == 1 && !(OI[OIDX(cur)].flags & 3)) {
                    n->type = NODE_NUMBER;
                    n->data.number.value = OI[OIDX(cur)].value;
                    return n;
                }
            } else if (!L) {
                int g = gidx(n->data.variable.name);
                if (g >= 0 && GCONST[g] && !GASS[g] && !GADDR[g] && !freestanding) {
                    n->type = NODE_NUMBER;
                    n->data.number.value = GVAL[g];
                    return n;
                }
            }
            return n;
        }
        case NODE_BINARY:
            n->data.binary.left = prop_expr(n->data.binary.left);
            n->data.binary.right = prop_expr(n->data.binary.right);
            return n;
        case NODE_NOT: case NODE_BNOT: case NODE_DEREF:
            n->data.unary.value = prop_expr(n->data.unary.value);
            return n;
        case NODE_ADDR: case NODE_SIZEOF:
            return n;
        case NODE_INDEX:
            n->data.index.base = prop_expr(n->data.index.base);
            n->data.index.index = prop_expr(n->data.index.index);
            return n;
        case NODE_MEMBER:
            n->data.member.base = prop_expr(n->data.member.base);
            return n;
        case NODE_ASSIGN:
            n->data.assign.rhs = prop_expr(n->data.assign.rhs);
            return n;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) n->data.call.args[i] = prop_expr(n->data.call.args[i]);
            return n;
        default:
            return n;
    }
}

static void prop_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            if (n->data.let.value) n->data.let.value = prop_expr(n->data.let.value);
            osc_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            osc_push();
            for (int i = 0; i < n->data.block.count; i++) prop_stmt(n->data.block.stmts[i]);
            osc_pop();
            break;
        case NODE_IF:
            n->data.if_node.cond = prop_expr(n->data.if_node.cond);
            osc_push(); prop_stmt(n->data.if_node.then); osc_pop();
            osc_push(); prop_stmt(n->data.if_node.else_); osc_pop();
            break;
        case NODE_WHILE:
            n->data.while_node.cond = prop_expr(n->data.while_node.cond);
            osc_push(); prop_stmt(n->data.while_node.body); osc_pop();
            break;
        case NODE_FOR:
            osc_push();
            prop_stmt(n->data.for_node.init);
            if (n->data.for_node.cond) n->data.for_node.cond = prop_expr(n->data.for_node.cond);
            if (n->data.for_node.inc) n->data.for_node.inc = prop_expr(n->data.for_node.inc);
            prop_stmt(n->data.for_node.body);
            osc_pop();
            break;
        case NODE_SWITCH:
            n->data.switch_node.expr = prop_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                osc_push(); prop_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); osc_pop();
            }
            break;
        case NODE_RETURN: n->data.return_node.value = prop_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) n->data.print.args[i] = prop_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: osc_n = 0; prop_stmt(n->data.function.body); break;
        default: prop_expr(n); break;
    }
}

static void prop_program(ASTNode *root) {
    osc_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) {
            if (n->data.let.value) n->data.let.value = prop_expr(n->data.let.value);
        } else { osc_n = 0; prop_stmt(n); }
    }
    osc_n = 0;
}

static void fb_block(ASTNode *b);
static void fb_norm(ASTNode **slot);
static void fb_recurse(ASTNode *s);
static void fb_emit(ASTNode *s, ASTNode ***out, int *n, int *cap);

static void fb_emit(ASTNode *s, ASTNode ***out, int *n, int *cap) {
    if (!s) return;
    if (s->type == NODE_BLOCK) {
        fb_block(s);
        for (int i = 0; i < s->data.block.count; i++) PUSH(*out, *n, *cap, s->data.block.stmts[i]);
    } else {
        fb_recurse(s);
        PUSH(*out, *n, *cap, s);
    }
}

static void fb_block(ASTNode *b) {
    if (!b) return;
    ASTNode **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        ASTNode *s = b->data.block.stmts[i];
        if (s->type == NODE_IF && s->data.if_node.cond->type == NODE_NUMBER) {
            fb_emit(s->data.if_node.cond->data.number.value ? s->data.if_node.then : s->data.if_node.else_,
                    &out, &n, &cap);
        } else if (s->type == NODE_WHILE && s->data.while_node.cond->type == NODE_NUMBER &&
                   !s->data.while_node.cond->data.number.value) {
        } else {
            fb_recurse(s);
            PUSH(out, n, cap, s);
        }
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static void fb_norm(ASTNode **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        ASTNode *b = node(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    fb_block(*slot);
}

static void fb_recurse(ASTNode *s) {
    if (!s) return;
    switch (s->type) {
        case NODE_IF: fb_norm(&s->data.if_node.then); fb_norm(&s->data.if_node.else_); break;
        case NODE_WHILE: fb_norm(&s->data.while_node.body); break;
        case NODE_FOR: fb_norm(&s->data.for_node.body); break;
        case NODE_SWITCH: for (int i = 0; i < s->data.switch_node.narms; i++) fb_block(s->data.switch_node.arms[i]->data.case_arm.blk); break;
        case NODE_BLOCK: fb_block(s); break;
        case NODE_FUNCTION: fb_block(s->data.function.body); break;
        default: break;
    }
}

#define VNCAP 4096
static struct { int tag, op, l, r; long value; char *name; int vn; } VK[VNCAP];
static int vk_n;
static int vnv[NODE_CAP];
static int vncnt[VNCAP];
static char *vntmp[VNCAP];
static int cse_id;
static struct { char *tmp; ASTNode *val; } *HOIST;
static int hn, hcap;

static void hoist_add(char *tmp, ASTNode *val) {
    if (hn >= hcap) { hcap = hcap ? hcap * 2 : 8; HOIST = realloc(HOIST, hcap * sizeof *HOIST); }
    HOIST[hn].tmp = tmp; HOIST[hn].val = val; hn++;
}

static void cse_reset(void) {
    for (int i = 0; i < vk_n; i++) { vncnt[i] = 0; vntmp[i] = NULL; }
    vk_n = 0;
    hn = 0;
}

static int vn_cons(int tag, int op, int l, int r, long value, const char *name) {
    for (int i = 0; i < vk_n; i++) {
        if (VK[i].tag != tag) continue;
        if (tag == 0) { if (VK[i].value != value) continue; }
        else if (tag == 1) { if (strcmp(VK[i].name, name)) continue; }
        else if (tag == 2) { if (VK[i].op != op || VK[i].l != l || VK[i].r != r) continue; }
        else { if (VK[i].l != l) continue; }
        return VK[i].vn;
    }
    VK[vk_n].tag = tag; VK[vk_n].op = op; VK[vk_n].l = l; VK[vk_n].r = r;
    VK[vk_n].value = value; VK[vk_n].name = (char *)name; VK[vk_n].vn = vk_n;
    return vk_n++;
}

static int vn_expr(ASTNode *n) {
    switch (n->type) {
        case NODE_NUMBER: return vn_cons(0, 0, 0, 0, n->data.number.value, NULL);
        case NODE_VARIABLE: return vn_cons(1, 0, 0, 0, 0, n->data.variable.name);
        case NODE_BINARY: {
            int l = vn_expr(n->data.binary.left);
            int r = vn_expr(n->data.binary.right);
            return vn_cons(2, n->data.binary.op, l, r, 0, NULL);
        }
        case NODE_NOT: return vn_cons(3, 0, vn_expr(n->data.unary.value), 0, 0, NULL);
        case NODE_BNOT: return vn_cons(4, 0, vn_expr(n->data.unary.value), 0, 0, NULL);
        default: return -1;
    }
}

static void cse_count_expr(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE: {
            int v = vn_expr(n); vnv[OIDX(n)] = v; vncnt[v]++;
            break;
        }
        case NODE_BINARY:
            cse_count_expr(n->data.binary.left);
            cse_count_expr(n->data.binary.right);
            { int v = vn_expr(n); vnv[OIDX(n)] = v; vncnt[v]++; }
            break;
        case NODE_NOT: case NODE_BNOT:
            cse_count_expr(n->data.unary.value);
            { int v = vn_expr(n); vnv[OIDX(n)] = v; vncnt[v]++; }
            break;
        default: break;
    }
}

static ASTNode *cse_rewrite_expr(ASTNode *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE:
            return n;
        case NODE_BINARY:
            n->data.binary.left = cse_rewrite_expr(n->data.binary.left);
            n->data.binary.right = cse_rewrite_expr(n->data.binary.right);
            break;
        case NODE_NOT: case NODE_BNOT:
            n->data.unary.value = cse_rewrite_expr(n->data.unary.value);
            break;
        default:
            return n;
    }
    int v = vnv[OIDX(n)];
    if (v >= 0 && vncnt[v] >= 2) {
        if (!vntmp[v]) {
            char buf[32];
            sprintf(buf, "$cse%d", cse_id++);
            vntmp[v] = str_put(buf, strlen(buf));
            hoist_add(vntmp[v], n);
        }
        return mk_var(vntmp[v], n->line);
    }
    return n;
}

static int cse_eligible(ASTNode *s) {
    switch (s->type) {
        case NODE_LET: return !s->data.let.value || is_spec_pure(s->data.let.value);
        case NODE_ASSIGN: return s->data.assign.lhs->type == NODE_VARIABLE && is_spec_pure(s->data.assign.rhs);
        case NODE_RETURN: return is_spec_pure(s->data.return_node.value);
        case NODE_PRINT:
            for (int i = 0; i < s->data.print.ncount; i++) if (!is_spec_pure(s->data.print.args[i])) return 0;
            return 1;
        default: return is_spec_pure(s);
    }
}

static void cse_do_stmt(ASTNode *s) {
    cse_reset();
    switch (s->type) {
        case NODE_LET: if (s->data.let.value) cse_count_expr(s->data.let.value); break;
        case NODE_ASSIGN: cse_count_expr(s->data.assign.rhs); break;
        case NODE_RETURN: cse_count_expr(s->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < s->data.print.ncount; i++) cse_count_expr(s->data.print.args[i]); break;
        default: cse_count_expr(s); break;
    }
    switch (s->type) {
        case NODE_LET: if (s->data.let.value) s->data.let.value = cse_rewrite_expr(s->data.let.value); break;
        case NODE_ASSIGN: s->data.assign.rhs = cse_rewrite_expr(s->data.assign.rhs); break;
        case NODE_RETURN: s->data.return_node.value = cse_rewrite_expr(s->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < s->data.print.ncount; i++) s->data.print.args[i] = cse_rewrite_expr(s->data.print.args[i]); break;
        default: cse_rewrite_expr(s); break;
    }
}

static void cse_block(ASTNode *b);
static void cse_sub(ASTNode **slot);

static void cse_sub(ASTNode **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        ASTNode *b = node(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    cse_block(*slot);
}

static void cse_block(ASTNode *b) {
    if (!b) return;
    ASTNode **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        ASTNode *s = b->data.block.stmts[i];
        switch (s->type) {
            case NODE_BLOCK: cse_block(s); break;
            case NODE_IF: cse_sub(&s->data.if_node.then); cse_sub(&s->data.if_node.else_); break;
            case NODE_WHILE: cse_sub(&s->data.while_node.body); break;
            case NODE_FOR: cse_sub(&s->data.for_node.body); break;
            case NODE_SWITCH: for (int k = 0; k < s->data.switch_node.narms; k++) cse_block(s->data.switch_node.arms[k]->data.case_arm.blk); break;
            case NODE_FUNCTION: cse_block(s->data.function.body); break;
            default: if (cse_eligible(s)) cse_do_stmt(s); break;
        }
        for (int k = 0; k < hn; k++) PUSH(out, n, cap, mk_let(HOIST[k].tmp, HOIST[k].val, s->line));
        hn = 0;
        PUSH(out, n, cap, s);
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static unsigned char used[NODE_CAP];

static void dce_count_expr(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_VARIABLE: {
            ASTNode *L = osc_find(n->data.variable.name);
            if (L) used[OIDX(L)] = 1;
            break;
        }
        case NODE_BINARY:
            dce_count_expr(n->data.binary.left);
            dce_count_expr(n->data.binary.right);
            break;
        case NODE_ASSIGN:
            dce_count_expr(n->data.assign.lhs);
            dce_count_expr(n->data.assign.rhs);
            break;
        case NODE_NOT: case NODE_BNOT: case NODE_ADDR: case NODE_DEREF: case NODE_SIZEOF:
            dce_count_expr(n->data.unary.value);
            break;
        case NODE_INDEX:
            dce_count_expr(n->data.index.base);
            dce_count_expr(n->data.index.index);
            break;
        case NODE_MEMBER:
            dce_count_expr(n->data.member.base);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) dce_count_expr(n->data.call.args[i]);
            break;
        default: break;
    }
}

static void dce_count_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            dce_count_expr(n->data.let.value);
            osc_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            osc_push();
            for (int i = 0; i < n->data.block.count; i++) dce_count_stmt(n->data.block.stmts[i]);
            osc_pop();
            break;
        case NODE_IF:
            dce_count_expr(n->data.if_node.cond);
            osc_push(); dce_count_stmt(n->data.if_node.then); osc_pop();
            osc_push(); dce_count_stmt(n->data.if_node.else_); osc_pop();
            break;
        case NODE_WHILE:
            dce_count_expr(n->data.while_node.cond);
            osc_push(); dce_count_stmt(n->data.while_node.body); osc_pop();
            break;
        case NODE_FOR:
            osc_push();
            dce_count_stmt(n->data.for_node.init);
            dce_count_expr(n->data.for_node.cond);
            dce_count_expr(n->data.for_node.inc);
            dce_count_stmt(n->data.for_node.body);
            osc_pop();
            break;
        case NODE_SWITCH:
            dce_count_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                osc_push(); dce_count_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); osc_pop();
            }
            break;
        case NODE_RETURN: dce_count_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) dce_count_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: osc_n = 0; dce_count_stmt(n->data.function.body); break;
        default: dce_count_expr(n); break;
    }
}

static void dce_count_program(ASTNode *root) {
    memset(used, 0, sizeof used);
    osc_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) continue;
        osc_n = 0;
        dce_count_stmt(n);
    }
    osc_n = 0;
}

static void dce_block(ASTNode *b, int top);
static void dce_sub(ASTNode **slot);
static void dce_recurse(ASTNode *s);

static void dce_sub(ASTNode **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        ASTNode *b = node(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    dce_block(*slot, 0);
}

static void dce_recurse(ASTNode *s) {
    if (!s) return;
    switch (s->type) {
        case NODE_IF: dce_sub(&s->data.if_node.then); dce_sub(&s->data.if_node.else_); break;
        case NODE_WHILE: dce_sub(&s->data.while_node.body); break;
        case NODE_FOR: {
            ASTNode *ini = s->data.for_node.init;
            if (ini) {
                if (ini->type == NODE_LET) {
                    if (!used[OIDX(ini)] && !has_side_effect(ini->data.let.value)) s->data.for_node.init = NULL;
                } else if (!has_side_effect(ini)) {
                    s->data.for_node.init = NULL;
                }
            }
            dce_sub(&s->data.for_node.body);
            break;
        }
        case NODE_SWITCH: for (int i = 0; i < s->data.switch_node.narms; i++) dce_block(s->data.switch_node.arms[i]->data.case_arm.blk, 0); break;
        case NODE_BLOCK: dce_block(s, 0); break;
        case NODE_FUNCTION: dce_block(s->data.function.body, 0); break;
        default: break;
    }
}

static void dce_block(ASTNode *b, int top) {
    if (!b) return;
    ASTNode **out = NULL; int n = 0, cap = 0; int terminated = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        ASTNode *s = b->data.block.stmts[i];
        if (terminated) continue;
        switch (s->type) {
            case NODE_LET:
                if (top) PUSH(out, n, cap, s);
                else if (s->data.let.value) {
                    if (has_side_effect(s->data.let.value) || used[OIDX(s)]) PUSH(out, n, cap, s);
                } else {
                    if (used[OIDX(s)]) PUSH(out, n, cap, s);
                }
                break;
            case NODE_IF: dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_WHILE: dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_FOR: dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_SWITCH: dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_BLOCK: dce_block(s, 0); PUSH(out, n, cap, s); break;
            case NODE_FUNCTION: dce_block(s->data.function.body, 0); PUSH(out, n, cap, s); break;
            case NODE_PRINT: dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_RETURN: dce_recurse(s); PUSH(out, n, cap, s); terminated = 1; break;
            case NODE_BREAK: case NODE_CONTINUE: PUSH(out, n, cap, s); terminated = 1; break;
            case NODE_EXTERN_FUNC: case NODE_EXTERN_GLOB: PUSH(out, n, cap, s); break;
            default:
                if (has_side_effect(s)) PUSH(out, n, cap, s);
                break;
        }
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static int tco_id;

static int tco_is_tail(ASTNode *n, const char *fname, int pcount) {
    if (!n || n->type != NODE_CALL || strcmp(n->data.call.name, fname)) return 0;
    if (n->data.call.acount != pcount) return 0;
    for (int i = 0; i < n->data.call.acount; i++)
        if (!is_spec_pure(n->data.call.args[i])) return 0;
    return 1;
}

static ASTNode *tco_replace(ASTNode *call, char **params, int pcount, int line) {
    ASTNode *b = node(NODE_BLOCK, line);
    char *tnames[64];
    for (int i = 0; i < pcount; i++) {
        char buf[32];
        sprintf(buf, "$tco%d", tco_id++);
        tnames[i] = str_put(buf, strlen(buf));
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, mk_let(tnames[i], call->data.call.args[i], line));
    }
    for (int i = 0; i < pcount; i++) {
        ASTNode *as = node(NODE_ASSIGN, line);
        as->data.assign.lhs = mk_var(params[i], line);
        as->data.assign.cop = 0;
        as->data.assign.rhs = mk_var(tnames[i], line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, as);
    }
    PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, node(NODE_CONTINUE, line));
    return b;
}

static void tco_stmt(ASTNode **slot, const char *fname, char **params, int pcount, int in_loop, int *found);
static void tco_block(ASTNode *b, const char *fname, char **params, int pcount, int in_loop, int *found) {
    if (!b) return;
    for (int i = 0; i < b->data.block.count; i++)
        tco_stmt(&b->data.block.stmts[i], fname, params, pcount, in_loop, found);
}
static void tco_stmt(ASTNode **slot, const char *fname, char **params, int pcount, int in_loop, int *found) {
    ASTNode *n = *slot;
    if (!n) return;
    switch (n->type) {
        case NODE_RETURN:
            if (!in_loop && n->data.return_node.value && tco_is_tail(n->data.return_node.value, fname, pcount)) {
                *slot = tco_replace(n->data.return_node.value, params, pcount, n->line);
                *found = 1;
            }
            break;
        case NODE_BLOCK:
            tco_block(n, fname, params, pcount, in_loop, found);
            break;
        case NODE_IF:
            tco_stmt(&n->data.if_node.then, fname, params, pcount, in_loop, found);
            tco_stmt(&n->data.if_node.else_, fname, params, pcount, in_loop, found);
            break;
        case NODE_WHILE:
            tco_stmt(&n->data.while_node.body, fname, params, pcount, 1, found);
            break;
        case NODE_FOR:
            tco_stmt(&n->data.for_node.init, fname, params, pcount, 1, found);
            tco_stmt(&n->data.for_node.body, fname, params, pcount, 1, found);
            break;
        case NODE_SWITCH:
            for (int i = 0; i < n->data.switch_node.narms; i++)
                tco_block(n->data.switch_node.arms[i]->data.case_arm.blk, fname, params, pcount, 1, found);
            break;
        default:
            break;
    }
}

static void tco_function(ASTNode *f) {
    if (f->data.function.naked || f->data.function.pcount > 64) return;
    int found = 0;
    tco_block(f->data.function.body, f->data.function.name, f->data.function.params, f->data.function.pcount, 0, &found);
    if (!found) return;
    ASTNode *loop = node(NODE_FOR, f->line);
    loop->data.for_node.init = NULL;
    loop->data.for_node.cond = NULL;
    loop->data.for_node.inc = NULL;
    loop->data.for_node.body = f->data.function.body;
    ASTNode *nb = node(NODE_BLOCK, f->line);
    PUSH(nb->data.block.stmts, nb->data.block.count, nb->data.block.cap, loop);
    f->data.function.body = nb;
}

static void tco_program(ASTNode *root) {
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION) tco_function(n);
    }
}

static char *licm_globals[256];
static int licm_nglob;
static char *licm_mod[256];
static int licm_nmod;
static int licm_has_call;
static int licm_memwrite;
static int licm_id;
static int licm_flag[VNCAP];
static char *licm_tmp[VNCAP];
static struct { char *tmp; ASTNode *val; } *licm_hoist;
static int licm_nhoist, licm_hcap;

static int licm_is_global(const char *name) {
    for (int i = 0; i < licm_nglob; i++) if (!strcmp(licm_globals[i], name)) return 1;
    return 0;
}
static int licm_mod_has(const char *name) {
    for (int i = 0; i < licm_nmod; i++) if (!strcmp(licm_mod[i], name)) return 1;
    return 0;
}
static void licm_mod_add(const char *name) {
    if (licm_nmod < 256 && !licm_mod_has(name)) licm_mod[licm_nmod++] = (char *)name;
}
static void licm_hoist_add(char *tmp, ASTNode *val) {
    if (licm_nhoist >= licm_hcap) { licm_hcap = licm_hcap ? licm_hcap * 2 : 8; licm_hoist = realloc(licm_hoist, licm_hcap * sizeof *licm_hoist); }
    licm_hoist[licm_nhoist].tmp = tmp; licm_hoist[licm_nhoist].val = val; licm_nhoist++;
}

static void licm_collect_expr(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_ASSIGN:
            if (n->data.assign.lhs->type == NODE_VARIABLE) licm_mod_add(n->data.assign.lhs->data.variable.name);
            else licm_memwrite = 1;
            licm_collect_expr(n->data.assign.lhs);
            licm_collect_expr(n->data.assign.rhs);
            break;
        case NODE_ADDR:
            if (n->data.unary.value->type == NODE_VARIABLE) licm_mod_add(n->data.unary.value->data.variable.name);
            else licm_collect_expr(n->data.unary.value);
            break;
        case NODE_CALL:
            licm_has_call = 1;
            for (int i = 0; i < n->data.call.acount; i++) licm_collect_expr(n->data.call.args[i]);
            break;
        case NODE_BINARY: licm_collect_expr(n->data.binary.left); licm_collect_expr(n->data.binary.right); break;
        case NODE_NOT: case NODE_BNOT: case NODE_DEREF: licm_collect_expr(n->data.unary.value); break;
        case NODE_INDEX: licm_collect_expr(n->data.index.base); licm_collect_expr(n->data.index.index); break;
        case NODE_MEMBER: licm_collect_expr(n->data.member.base); break;
        default: break;
    }
}

static void licm_collect_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET: licm_collect_expr(n->data.let.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) licm_collect_expr(n->data.print.args[i]); break;
        case NODE_RETURN: licm_collect_expr(n->data.return_node.value); break;
        case NODE_IF: licm_collect_expr(n->data.if_node.cond); licm_collect_stmt(n->data.if_node.then); licm_collect_stmt(n->data.if_node.else_); break;
        case NODE_WHILE: licm_collect_expr(n->data.while_node.cond); licm_collect_stmt(n->data.while_node.body); break;
        case NODE_FOR: licm_collect_stmt(n->data.for_node.init); licm_collect_expr(n->data.for_node.cond); licm_collect_expr(n->data.for_node.inc); licm_collect_stmt(n->data.for_node.body); break;
        case NODE_SWITCH: licm_collect_expr(n->data.switch_node.expr); for (int i = 0; i < n->data.switch_node.narms; i++) licm_collect_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); break;
        case NODE_BLOCK: for (int i = 0; i < n->data.block.count; i++) licm_collect_stmt(n->data.block.stmts[i]); break;
        default: licm_collect_expr(n); break;
    }
}

static int licm_invariant(ASTNode *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_NUMBER: return 1;
        case NODE_VARIABLE: {
            const char *name = n->data.variable.name;
            if (licm_mod_has(name)) return 0;
            if (licm_has_call || licm_memwrite) return 0;
            if (freestanding && licm_is_global(name)) return 0;
            return 1;
        }
        case NODE_BINARY:
            if (n->data.binary.op == OP_DIV || n->data.binary.op == OP_MOD) return 0;
            return licm_invariant(n->data.binary.left) && licm_invariant(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT: return licm_invariant(n->data.unary.value);
        default: return 0;
    }
}

static int licm_worth(ASTNode *n) {
    if (n->type != NODE_BINARY) return 0;
    ASTNode *l = n->data.binary.left, *r = n->data.binary.right;
    return l->type == NODE_BINARY || l->type == NODE_NOT || l->type == NODE_BNOT ||
           r->type == NODE_BINARY || r->type == NODE_NOT || r->type == NODE_BNOT;
}

static void licm_reset(void) {
    for (int i = 0; i < vk_n; i++) { licm_flag[i] = 0; licm_tmp[i] = NULL; }
    vk_n = 0;
    licm_nhoist = 0;
}

static void licm_count_expr(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE: { int v = vn_expr(n); vnv[OIDX(n)] = v; break; }
        case NODE_BINARY:
            licm_count_expr(n->data.binary.left);
            licm_count_expr(n->data.binary.right);
            { int v = vn_expr(n); vnv[OIDX(n)] = v; if (licm_worth(n) && licm_invariant(n)) licm_flag[v] = 1; }
            break;
        case NODE_NOT: case NODE_BNOT:
            licm_count_expr(n->data.unary.value);
            { int v = vn_expr(n); vnv[OIDX(n)] = v; }
            break;
        default: break;
    }
}

static void licm_count_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET: licm_count_expr(n->data.let.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) licm_count_expr(n->data.print.args[i]); break;
        case NODE_RETURN: licm_count_expr(n->data.return_node.value); break;
        case NODE_ASSIGN: licm_count_expr(n->data.assign.rhs); break;
        case NODE_IF: licm_count_expr(n->data.if_node.cond); licm_count_stmt(n->data.if_node.then); licm_count_stmt(n->data.if_node.else_); break;
        case NODE_WHILE: licm_count_expr(n->data.while_node.cond); licm_count_stmt(n->data.while_node.body); break;
        case NODE_FOR: licm_count_stmt(n->data.for_node.init); licm_count_expr(n->data.for_node.cond); licm_count_expr(n->data.for_node.inc); licm_count_stmt(n->data.for_node.body); break;
        case NODE_SWITCH: licm_count_expr(n->data.switch_node.expr); for (int i = 0; i < n->data.switch_node.narms; i++) licm_count_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); break;
        case NODE_BLOCK: for (int i = 0; i < n->data.block.count; i++) licm_count_stmt(n->data.block.stmts[i]); break;
        default: licm_count_expr(n); break;
    }
}

static ASTNode *licm_rewrite_expr(ASTNode *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE: return n;
        case NODE_BINARY:
            n->data.binary.left = licm_rewrite_expr(n->data.binary.left);
            n->data.binary.right = licm_rewrite_expr(n->data.binary.right);
            break;
        case NODE_NOT: case NODE_BNOT:
            n->data.unary.value = licm_rewrite_expr(n->data.unary.value);
            break;
        default: return n;
    }
    int v = vnv[OIDX(n)];
    if (v >= 0 && licm_flag[v]) {
        if (!licm_tmp[v]) {
            char buf[32];
            sprintf(buf, "$licm%d", licm_id++);
            licm_tmp[v] = str_put(buf, strlen(buf));
            licm_hoist_add(licm_tmp[v], n);
        }
        return mk_var(licm_tmp[v], n->line);
    }
    return n;
}

static void licm_rewrite_stmt(ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET: n->data.let.value = licm_rewrite_expr(n->data.let.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) n->data.print.args[i] = licm_rewrite_expr(n->data.print.args[i]); break;
        case NODE_RETURN: n->data.return_node.value = licm_rewrite_expr(n->data.return_node.value); break;
        case NODE_ASSIGN: n->data.assign.rhs = licm_rewrite_expr(n->data.assign.rhs); break;
        case NODE_IF: n->data.if_node.cond = licm_rewrite_expr(n->data.if_node.cond); licm_rewrite_stmt(n->data.if_node.then); licm_rewrite_stmt(n->data.if_node.else_); break;
        case NODE_WHILE: n->data.while_node.cond = licm_rewrite_expr(n->data.while_node.cond); licm_rewrite_stmt(n->data.while_node.body); break;
        case NODE_FOR: licm_rewrite_stmt(n->data.for_node.init); n->data.for_node.cond = licm_rewrite_expr(n->data.for_node.cond); n->data.for_node.inc = licm_rewrite_expr(n->data.for_node.inc); licm_rewrite_stmt(n->data.for_node.body); break;
        case NODE_SWITCH: n->data.switch_node.expr = licm_rewrite_expr(n->data.switch_node.expr); for (int i = 0; i < n->data.switch_node.narms; i++) licm_rewrite_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); break;
        case NODE_BLOCK: for (int i = 0; i < n->data.block.count; i++) licm_rewrite_stmt(n->data.block.stmts[i]); break;
        default: break;
    }
}

static void licm_loop(ASTNode *s) {
    licm_nmod = 0; licm_has_call = 0; licm_memwrite = 0;
    if (s->type == NODE_WHILE) {
        licm_collect_expr(s->data.while_node.cond);
        licm_collect_stmt(s->data.while_node.body);
    } else {
        licm_collect_stmt(s->data.for_node.init);
        licm_collect_expr(s->data.for_node.cond);
        licm_collect_expr(s->data.for_node.inc);
        licm_collect_stmt(s->data.for_node.body);
    }
    licm_reset();
    if (s->type == NODE_WHILE) {
        licm_count_expr(s->data.while_node.cond);
        licm_count_stmt(s->data.while_node.body);
    } else {
        licm_count_stmt(s->data.for_node.init);
        licm_count_expr(s->data.for_node.cond);
        licm_count_expr(s->data.for_node.inc);
        licm_count_stmt(s->data.for_node.body);
    }
    if (s->type == NODE_WHILE) {
        s->data.while_node.cond = licm_rewrite_expr(s->data.while_node.cond);
        licm_rewrite_stmt(s->data.while_node.body);
    } else {
        licm_rewrite_stmt(s->data.for_node.init);
        s->data.for_node.cond = licm_rewrite_expr(s->data.for_node.cond);
        s->data.for_node.inc = licm_rewrite_expr(s->data.for_node.inc);
        licm_rewrite_stmt(s->data.for_node.body);
    }
}

static void licm_block(ASTNode *b);
static void licm_sub(ASTNode **slot);

static void licm_block(ASTNode *b) {
    if (!b) return;
    ASTNode **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        ASTNode *s = b->data.block.stmts[i];
        switch (s->type) {
            case NODE_BLOCK: licm_block(s); break;
            case NODE_IF: licm_sub(&s->data.if_node.then); licm_sub(&s->data.if_node.else_); break;
            case NODE_FUNCTION: licm_block(s->data.function.body); break;
            case NODE_SWITCH: for (int k = 0; k < s->data.switch_node.narms; k++) licm_block(s->data.switch_node.arms[k]->data.case_arm.blk); break;
            case NODE_WHILE: case NODE_FOR:
                if (s->type == NODE_WHILE) licm_sub(&s->data.while_node.body);
                else licm_sub(&s->data.for_node.body);
                licm_loop(s);
                for (int k = 0; k < licm_nhoist; k++) PUSH(out, n, cap, mk_let(licm_hoist[k].tmp, licm_hoist[k].val, s->line));
                licm_nhoist = 0;
                break;
            default: break;
        }
        PUSH(out, n, cap, s);
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static void licm_sub(ASTNode **slot) {
    if (!*slot) return;
    if ((*slot)->type == NODE_BLOCK) { licm_block(*slot); return; }
    ASTNode *s = *slot;
    if (s->type == NODE_WHILE || s->type == NODE_FOR) {
        if (s->type == NODE_WHILE) licm_sub(&s->data.while_node.body);
        else licm_sub(&s->data.for_node.body);
        licm_loop(s);
        if (licm_nhoist) {
            ASTNode *b = node(NODE_BLOCK, s->line);
            for (int k = 0; k < licm_nhoist; k++) PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, mk_let(licm_hoist[k].tmp, licm_hoist[k].val, s->line));
            PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, s);
            licm_nhoist = 0;
            *slot = b;
        }
        return;
    }
    switch (s->type) {
        case NODE_IF: licm_sub(&s->data.if_node.then); licm_sub(&s->data.if_node.else_); break;
        case NODE_SWITCH: for (int i = 0; i < s->data.switch_node.narms; i++) licm_block(s->data.switch_node.arms[i]->data.case_arm.blk); break;
        default: break;
    }
}

static void licm_program(ASTNode *root) {
    licm_nglob = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) licm_globals[licm_nglob++] = n->data.let.name;
    }
    licm_block(root);
}

static void optimize_program(ASTNode *root) {
    tco_program(root);
    opt_fold_block(root);
    analyze_program(root);
    prop_program(root);
    opt_fold_block(root);
    fb_block(root);
    licm_program(root);
    cse_block(root);
    dce_count_program(root);
    dce_block(root, 1);
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

static const uint8_t BOOT_SEC[287] = {
    0xfa, 0x31, 0xc0, 0x8e, 0xd8, 0x8e, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c,
    0xb8, 0x00, 0x10, 0x8e, 0xc0, 0x31, 0xdb, 0xbe, 0x0f, 0x7d, 0xb4, 0x42,
    0xcd, 0x13, 0x90, 0x90, 0x90, 0x90, 0x90, 0x72, 0x18, 0xe4, 0x92, 0x0c,
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
    0xc0, 0x1f, 0x00, 0xe7, 0x7c, 0x00, 0x00,
    0x10, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void write_bin(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }
    if (boot_mode) {
        static uint8_t z[65536];
        if (clen + gsize > 65024) {
            fprintf(stderr, "error: kernel image exceeds 65024 bytes (%d)\n", clen + gsize);
            exit(1);
        }
        int kern = clen + gsize;
        int sectors = (kern + 511) / 512;
        uint8_t stage1[sizeof BOOT_SEC];
        memcpy(stage1, BOOT_SEC, sizeof BOOT_SEC);
        for (int i = 0; i + 8 < (int)sizeof stage1; i++)
            if (stage1[i] == 0x10 && stage1[i + 1] == 0x00 && stage1[i + 2] == 0xFF && stage1[i + 3] == 0xFF &&
                stage1[i + 4] == 0x00 && stage1[i + 5] == 0x00 && stage1[i + 6] == 0x00 && stage1[i + 7] == 0x10 && stage1[i + 8] == 0x01) {
                stage1[i + 2] = (uint8_t)(sectors & 0xFF);
                stage1[i + 3] = (uint8_t)((sectors >> 8) & 0xFF);
                break;
            }
        int qwords = (kern + 7) / 8;
        for (int i = 0; i + 4 < (int)sizeof stage1; i++)
            if (stage1[i] == 0xB9 && stage1[i + 1] == 0x00 && stage1[i + 2] == 0x04 && stage1[i + 3] == 0x00 && stage1[i + 4] == 0x00) {
                stage1[i + 1] = (uint8_t)(qwords & 0xFF);
                stage1[i + 2] = (uint8_t)((qwords >> 8) & 0xFF);
                stage1[i + 3] = (uint8_t)((qwords >> 16) & 0xFF);
                stage1[i + 4] = (uint8_t)((qwords >> 24) & 0xFF);
                break;
            }
        write(fd, stage1, sizeof stage1);
        write(fd, z, 510 - (int)sizeof BOOT_SEC);
        write(fd, "\x55\xAA", 2);
        write(fd, code, clen);
        if (gsize > 0) write(fd, z, gsize);
        write(fd, z, sectors * 512 - kern);
        close(fd);
        printf("  boot disk: 512-byte boot sector + %d kernel sector(s) = %d bytes (%d code + %d bss)\n",
               sectors, 512 + sectors * 512, clen, gsize);
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

typedef enum { T_I1, T_I8, T_I64, T_PTR, T_VOID } ITy;
typedef enum { K_CONST, K_REG, K_GLOBAL, K_FUNC, K_LIT } VKind;
typedef struct { VKind k; long c; int id; const char *nm; } V;

typedef enum {
    OP_BIN, OP_ICMP, OP_LOAD, OP_STORE, OP_ALLOCA, OP_CALL, OP_BR, OP_CBR, OP_RET, OP_PRINT, OP_ZEXT, OP_TRUNC, OP_GADDR,
    OP_PTRADD, OP_SYSCALL, OP_COPY, OP_PHI, OP_DEAD
} IOp;

typedef struct I {
    IOp op; ITy ty; int sub; int dst; V a, b; int t1, t2;
    V *args; int nargs; int *ppred;
    const char *nm;
    long bytes;
    int mk;
    struct I *next;
} I;

typedef struct B { int id; char nm[16]; I *head, *tail; struct B *next; } B;
typedef struct F { const char *nm; int np; char **params; int preg[16]; B *blocks, *cur; struct F *next; } F;

static F *ir_funcs;
static int ir_nreg = 1, ir_nblk = 0;
static int ir_brk = -1, ir_cont = -1;

static struct { const char *nm; ITy ty; long init; int has_init; Type *gast; } ir_globals[256];
static int ir_nglob;
static struct { const char *data; int len; } ir_strs[256];
static int ir_nstr;

enum { B_ADD, B_SUB, B_MUL, B_SDIV, B_SREM, B_AND, B_OR, B_XOR, B_SHL, B_SAR };
enum { C_EQ, C_NE, C_SLT, C_SLE, C_SGT, C_SGE };

static ITy ir_ty(Type *t) {
    if (!t) return T_I64;
    if (t->kind == 1 || t->kind == 2 || t->kind == 3) return T_PTR;
    return t->sz == 1 ? T_I8 : T_I64;
}

static V kconst(long c) { V v = { K_CONST, c, 0, NULL }; return v; }
static V kreg(int id) { V v = { K_REG, 0, id, NULL }; return v; }

static B *ir_newblock(F *f, const char *hint) {
    B *b = calloc(1, sizeof *b);
    b->id = ir_nblk++;
    sprintf(b->nm, "L%d", b->id);
    (void)hint;
    if (f->blocks) { B *p = f->blocks; while (p->next) p = p->next; p->next = b; }
    else f->blocks = b;
    return b;
}

static I *ir_emit(F *f, IOp op) {
    I *in = calloc(1, sizeof *in);
    in->op = op; in->dst = -1;
    if (f->cur->tail) { f->cur->tail->next = in; f->cur->tail = in; }
    else { f->cur->head = f->cur->tail = in; }
    return in;
}

static V ir_bin(F *f, int sub, V a, V b) {
    I *in = ir_emit(f, OP_BIN); in->sub = sub; in->ty = T_I64; in->dst = ir_nreg++; in->a = a; in->b = b;
    return kreg(in->dst);
}
static V ir_icmp(F *f, int sub, V a, V b) {
    I *in = ir_emit(f, OP_ICMP); in->sub = sub; in->ty = T_I1; in->dst = ir_nreg++; in->a = a; in->b = b;
    return kreg(in->dst);
}
static V ir_alloca(F *f, ITy ty, long bytes) {
    I *in = ir_emit(f, OP_ALLOCA); in->ty = ty; in->dst = ir_nreg++; in->bytes = bytes;
    return kreg(in->dst);
}
static V ir_ptradd(F *f, V a, V b) {
    I *in = ir_emit(f, OP_PTRADD); in->ty = T_PTR; in->dst = ir_nreg++; in->a = a; in->b = b;
    return kreg(in->dst);
}
static V ir_load(F *f, ITy ty, V p) {
    I *in = ir_emit(f, OP_LOAD); in->ty = ty; in->dst = ir_nreg++; in->a = p;
    return kreg(in->dst);
}
static void ir_store(F *f, ITy ty, V v, V p) {
    I *in = ir_emit(f, OP_STORE); in->ty = ty; in->a = v; in->b = p;
}
static V ir_zext(F *f, V a) {
    I *in = ir_emit(f, OP_ZEXT); in->ty = T_I64; in->dst = ir_nreg++; in->a = a;
    return kreg(in->dst);
}
static V ir_trunc(F *f, V a) {
    I *in = ir_emit(f, OP_TRUNC); in->ty = T_I8; in->dst = ir_nreg++; in->a = a;
    return kreg(in->dst);
}
static V ir_gaddr(F *f, const char *nm) {
    I *in = ir_emit(f, OP_GADDR); in->ty = T_PTR; in->dst = ir_nreg++; in->nm = nm;
    return kreg(in->dst);
}

static int ir_terminated(F *f) {
    if (!f->cur->tail) return 0;
    IOp op = f->cur->tail->op;
    return op == OP_RET || op == OP_BR || op == OP_CBR;
}

static struct { const char *nm; V val; ITy ty; Type *ast; } ir_sym[4096];
static int ir_symn;
static int ir_lookup(const char *nm, V *val, ITy *ty) {
    for (int i = ir_symn - 1; i >= 0; i--) {
        if (!strcmp(ir_sym[i].nm, nm)) { *val = ir_sym[i].val; *ty = ir_sym[i].ty; return 1; }
    }
    return 0;
}
static Type *ir_sym_ast(const char *nm) {
    for (int i = ir_symn - 1; i >= 0; i--)
        if (!strcmp(ir_sym[i].nm, nm)) return ir_sym[i].ast;
    return NULL;
}
static void ir_bind(const char *nm, V val, ITy ty, Type *ast) {
    ir_sym[ir_symn].nm = nm; ir_sym[ir_symn].val = val; ir_sym[ir_symn].ty = ty; ir_sym[ir_symn].ast = ast; ir_symn++;
}
static ITy ir_global_ty(const char *nm) {
    for (int i = 0; i < ir_nglob; i++) if (!strcmp(ir_globals[i].nm, nm)) return ir_globals[i].ty;
    return T_I64;
}
static Type *ir_global_ast(const char *nm) {
    for (int i = 0; i < ir_nglob; i++) if (!strcmp(ir_globals[i].nm, nm)) return ir_globals[i].gast;
    return NULL;
}

static int map_bin(BinOp op) {
    switch (op) {
        case OP_SUB: return B_SUB;
        case OP_MUL: return B_MUL;
        case OP_DIV: return B_SDIV;
        case OP_MOD: return B_SREM;
        case OP_BAND: return B_AND;
        case OP_BOR: return B_OR;
        case OP_BXOR: return B_XOR;
        case OP_SHL: return B_SHL;
        case OP_SHR: return B_SAR;
        default: return B_ADD;
    }
}
static int map_cmp(BinOp op) {
    switch (op) {
        case OP_NE: return C_NE;
        case OP_LT: return C_SLT;
        case OP_LE: return C_SLE;
        case OP_GT: return C_SGT;
        case OP_GE: return C_SGE;
        default: return C_EQ;
    }
}

static V lower_expr(F *f, ASTNode *n);
static void lower_stmt(F *f, ASTNode *n);

static Type *ir_expr_ty(ASTNode *n);

static Type *ir_var_ty(const char *nm) {
    Type *t = ir_sym_ast(nm);
    if (t) return t;
    t = ir_global_ast(nm);
    return t ? t : &TY_INT;
}

static Type *ir_struct_of(ASTNode *b, int arrow) {
    Type *bt = ir_expr_ty(b);
    if (arrow) { if (bt->kind != 1) die("-> applied to non-pointer", b->line); bt = bt->base; }
    if (!bt || bt->kind != 3) die("member access on non-struct", b->line);
    return bt;
}

static int ir_is_char_ty(Type *t) { return t && t->kind == 0 && t->sz == 1; }
static ITy ir_mem_ty(Type *t) { return ir_is_char_ty(t) ? T_I8 : T_I64; }

static Type *ir_expr_ty(ASTNode *n) {
    switch (n->type) {
        case NODE_VARIABLE: return ir_var_ty(n->data.variable.name);
        case NODE_STR:      return ty_ptr(&TY_CHAR);
        case NODE_DEREF:  { Type *t = ir_expr_ty(n->data.unary.value); return t->kind ? t->base : &TY_INT; }
        case NODE_INDEX:  { Type *t = ir_expr_ty(n->data.index.base); return t->kind ? t->base : &TY_INT; }
        case NODE_ADDR:     return ty_ptr(ir_expr_ty(n->data.unary.value));
        case NODE_MEMBER: {
            Field *fl = struct_field(ir_struct_of(n->data.member.base, n->data.member.arrow), n->data.member.field);
            if (!fl) die("no such field", n->line);
            return fl->ty;
        }
        default: return &TY_INT;
    }
}

static V lower_addr(F *f, ASTNode *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            V p; ITy ty;
            if (ir_lookup(n->data.variable.name, &p, &ty)) return p;
            return ir_gaddr(f, n->data.variable.name);
        }
        case NODE_DEREF: return lower_expr(f, n->data.unary.value);
        case NODE_INDEX: {
            Type *bt = ir_expr_ty(n->data.index.base);
            V base = bt->kind == 1 ? lower_expr(f, n->data.index.base) : lower_addr(f, n->data.index.base);
            V iv = lower_expr(f, n->data.index.index);
            int es = ty_size(ir_expr_ty(n));
            if (es != 1 && es != 8) iv = ir_bin(f, B_MUL, iv, kconst(es));
            else if (es == 8) iv = ir_bin(f, B_SHL, iv, kconst(3));
            return ir_ptradd(f, base, iv);
        }
        case NODE_MEMBER: {
            Field *fl = struct_field(ir_struct_of(n->data.member.base, n->data.member.arrow), n->data.member.field);
            if (!fl) die("no such field", n->line);
            V base = n->data.member.arrow ? lower_expr(f, n->data.member.base) : lower_addr(f, n->data.member.base);
            if (fl->off) return ir_bin(f, B_ADD, base, kconst(fl->off));
            return base;
        }
        default: die("not addressable", n->line); return kconst(0);
    }
}

static int ir_is_str_arg(ASTNode *e) {
    Type *t = ir_expr_ty(e);
    return (t->kind == 1 || t->kind == 2) && is_char(t->base);
}

static V lower_logic(F *f, ASTNode *n) {
    int is_and = n->data.binary.op == OP_AND;
    V tmp = ir_alloca(f, T_I1, 8);
    V a = lower_expr(f, n->data.binary.left);
    V ac = ir_icmp(f, C_NE, a, kconst(0));
    B *rhs = ir_newblock(f, "logic.rhs");
    B *sc = ir_newblock(f, "logic.sc");
    B *end = ir_newblock(f, "logic.end");
    I *cbr = ir_emit(f, OP_CBR); cbr->a = ac; cbr->t1 = is_and ? rhs->id : sc->id; cbr->t2 = is_and ? sc->id : rhs->id;
    f->cur = sc;
    ir_store(f, T_I1, is_and ? kconst(0) : kconst(1), tmp);
    ir_emit(f, OP_BR)->t1 = end->id;
    f->cur = rhs;
    V b = lower_expr(f, n->data.binary.right);
    V bc = ir_icmp(f, C_NE, b, kconst(0));
    ir_store(f, T_I1, bc, tmp);
    ir_emit(f, OP_BR)->t1 = end->id;
    f->cur = end;
    return ir_load(f, T_I1, tmp);
}

static V lower_expr(F *f, ASTNode *n) {
    switch (n->type) {
        case NODE_NUMBER: return kconst(n->data.number.value);
        case NODE_VARIABLE: {
            V p; ITy ty;
            Type *ast = ir_sym_ast(n->data.variable.name);
            if (ir_lookup(n->data.variable.name, &p, &ty)) {
                if (ast && ast->kind == 2) return p;
            } else {
                p = ir_gaddr(f, n->data.variable.name);
                ty = ir_global_ty(n->data.variable.name);
                ast = ir_global_ast(n->data.variable.name);
                if (ast && ast->kind == 2) return p;
            }
            V v = ir_load(f, ty, p);
            return ty == T_I8 ? ir_zext(f, v) : v;
        }
        case NODE_STR: {
            char nm[16];
            sprintf(nm, ".str%d", ir_nstr);
            ir_strs[ir_nstr].data = (const char *)(LIT + n->data.str.off);
            ir_strs[ir_nstr].len = n->data.str.len;
            ir_nstr++;
            V v = { K_LIT, n->data.str.off, 0, str_put(nm, strlen(nm)) };
            return v;
        }
        case NODE_BINARY: {
            BinOp op = n->data.binary.op;
            if (op == OP_AND || op == OP_OR) return lower_logic(f, n);
            V a = lower_expr(f, n->data.binary.left);
            V b = lower_expr(f, n->data.binary.right);
            if (op >= OP_EQ && op <= OP_GE) return ir_icmp(f, map_cmp(op), a, b);
            return ir_bin(f, map_bin(op), a, b);
        }
        case NODE_NOT: {
            V a = lower_expr(f, n->data.unary.value);
            return ir_icmp(f, C_EQ, a, kconst(0));
        }
        case NODE_BNOT: {
            V a = lower_expr(f, n->data.unary.value);
            return ir_bin(f, B_XOR, a, kconst(-1));
        }
        case NODE_SIZEOF: {
            ASTNode *u = n->data.unary.value;
            int sz = 8;
            if (u->type == NODE_VARIABLE) sz = ty_size(ir_var_ty(u->data.variable.name));
            return kconst(sz);
        }
        case NODE_ADDR: return lower_addr(f, n->data.unary.value);
        case NODE_DEREF: {
            V p = lower_expr(f, n->data.unary.value);
            ITy lt = ir_mem_ty(ir_expr_ty(n));
            V v = ir_load(f, lt, p);
            return lt == T_I8 ? ir_zext(f, v) : v;
        }
        case NODE_INDEX: {
            V p = lower_addr(f, n);
            ITy lt = ir_mem_ty(ir_expr_ty(n));
            V v = ir_load(f, lt, p);
            return lt == T_I8 ? ir_zext(f, v) : v;
        }
        case NODE_MEMBER: {
            Type *ft = ir_expr_ty(n);
            V p = lower_addr(f, n);
            if (ft->kind == 2 || ft->kind == 3) return p;
            V v = ir_load(f, ir_mem_ty(ft), p);
            return ir_mem_ty(ft) == T_I8 ? ir_zext(f, v) : v;
        }
        case NODE_ASSIGN: {
            V rhs = lower_expr(f, n->data.assign.rhs);
            if (n->data.assign.lhs->type == NODE_VARIABLE) {
                V p; ITy ty;
                if (!ir_lookup(n->data.assign.lhs->data.variable.name, &p, &ty)) {
                    p = ir_gaddr(f, n->data.assign.lhs->data.variable.name);
                    ty = ir_global_ty(n->data.assign.lhs->data.variable.name);
                }
                if (n->data.assign.cop) {
                    V cur = ir_load(f, ty, p);
                    if (ty == T_I8) cur = ir_zext(f, cur);
                    rhs = ir_bin(f, map_bin((BinOp)(n->data.assign.cop - 1)), cur, rhs);
                }
                if (ty == T_I8) rhs = ir_trunc(f, rhs);
                ir_store(f, ty, rhs, p);
                return rhs;
            }
            V p = lower_addr(f, n->data.assign.lhs);
            ITy lt = ir_mem_ty(ir_expr_ty(n->data.assign.lhs));
            if (n->data.assign.cop) {
                V cur = ir_load(f, lt, p);
                if (lt == T_I8) cur = ir_zext(f, cur);
                rhs = ir_bin(f, map_bin((BinOp)(n->data.assign.cop - 1)), cur, rhs);
            }
            if (lt == T_I8) rhs = ir_trunc(f, rhs);
            ir_store(f, lt, rhs, p);
            return rhs;
        }
        case NODE_CALL: {
            const char *nm = n->data.call.name;
            int na = n->data.call.acount;
            if (!strcmp(nm, "syscall") && fn_find("syscall") < 0) {
                if (na != 4) die("syscall(nr, a, b, c)", n->line);
                V args[4];
                for (int i = 0; i < 4; i++) args[i] = lower_expr(f, n->data.call.args[i]);
                I *in = ir_emit(f, OP_SYSCALL);
                in->dst = ir_nreg++; in->ty = T_I64; in->nargs = 4;
                in->args = malloc(4 * sizeof(V));
                for (int i = 0; i < 4; i++) in->args[i] = args[i];
                return kreg(in->dst);
            }
            if (!strcmp(nm, "addr") && fn_find("addr") < 0 && na == 1)
                return lower_addr(f, n->data.call.args[0]);
            if (fn_find(nm) < 0) {
                die("call to undefined function (IR backend)", n->line);
            }
            V args[64];
            for (int i = 0; i < na; i++) args[i] = lower_expr(f, n->data.call.args[i]);
            I *in = ir_emit(f, OP_CALL);
            in->dst = ir_nreg++; in->ty = T_I64;
            in->nm = nm;
            in->args = na ? malloc(na * sizeof(V)) : NULL;
            in->nargs = na;
            for (int i = 0; i < na; i++) in->args[i] = args[i];
            return kreg(in->dst);
        }
        default:
            return kconst(0);
    }
}

static void lower_print(F *f, ASTNode *n) {
    for (int i = 0; i < n->data.print.ncount; i++) {
        ASTNode *a = n->data.print.args[i];
        V v = lower_expr(f, a);
        I *in = ir_emit(f, OP_PRINT);
        in->sub = ir_is_str_arg(a) ? 1 : 0;
        in->a = v;
    }
}

static void lower_stmt(F *f, ASTNode *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET: {
            Type *ast = n->data.let.ty;
            ITy ty = ir_ty(ast);
            long bytes = (ast->kind == 2 || ast->kind == 3) ? ty_size(ast) : 8;
            V p = ir_alloca(f, ty, bytes);
            if (n->data.let.value) {
                V v = lower_expr(f, n->data.let.value);
                if (ty == T_I8) v = ir_trunc(f, v);
                ir_store(f, ty, v, p);
            }
            ir_bind(n->data.let.name, p, ty, ast);
            break;
        }
        case NODE_BLOCK: {
            int sn = ir_symn;
            for (int i = 0; i < n->data.block.count; i++) lower_stmt(f, n->data.block.stmts[i]);
            ir_symn = sn;
            break;
        }
        case NODE_IF: {
            V c = lower_expr(f, n->data.if_node.cond);
            B *then = ir_newblock(f, "then");
            B *els = n->data.if_node.else_ ? ir_newblock(f, "else") : NULL;
            B *merge = ir_newblock(f, "merge");
            I *cbr = ir_emit(f, OP_CBR); cbr->a = c; cbr->t1 = then->id; cbr->t2 = els ? els->id : merge->id;
            f->cur = then; lower_stmt(f, n->data.if_node.then); if (!ir_terminated(f)) ir_emit(f, OP_BR)->t1 = merge->id;
            if (els) { f->cur = els; lower_stmt(f, n->data.if_node.else_); if (!ir_terminated(f)) ir_emit(f, OP_BR)->t1 = merge->id; }
            f->cur = merge;
            break;
        }
        case NODE_WHILE: {
            B *header = ir_newblock(f, "while.h");
            B *body = ir_newblock(f, "while.b");
            B *end = ir_newblock(f, "while.e");
            ir_emit(f, OP_BR)->t1 = header->id;
            f->cur = header;
            V c = lower_expr(f, n->data.while_node.cond);
            I *cbr = ir_emit(f, OP_CBR); cbr->a = c; cbr->t1 = body->id; cbr->t2 = end->id;
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = header->id;
            f->cur = body; lower_stmt(f, n->data.while_node.body); if (!ir_terminated(f)) ir_emit(f, OP_BR)->t1 = header->id;
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_FOR: {
            if (n->data.for_node.init) lower_stmt(f, n->data.for_node.init);
            B *header = ir_newblock(f, "for.h");
            B *body = ir_newblock(f, "for.b");
            B *cont = ir_newblock(f, "for.c");
            B *end = ir_newblock(f, "for.e");
            ir_emit(f, OP_BR)->t1 = header->id;
            f->cur = header;
            if (n->data.for_node.cond) {
                V c = lower_expr(f, n->data.for_node.cond);
                I *cbr = ir_emit(f, OP_CBR); cbr->a = c; cbr->t1 = body->id; cbr->t2 = end->id;
            } else ir_emit(f, OP_BR)->t1 = body->id;
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = cont->id;
            f->cur = body; lower_stmt(f, n->data.for_node.body); if (!ir_terminated(f)) ir_emit(f, OP_BR)->t1 = cont->id;
            f->cur = cont;
            if (n->data.for_node.inc) lower_expr(f, n->data.for_node.inc);
            ir_emit(f, OP_BR)->t1 = header->id;
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_RETURN: {
            if (n->data.return_node.value) {
                V v = lower_expr(f, n->data.return_node.value);
                I *in = ir_emit(f, OP_RET); in->a = v; in->ty = T_I64;
            } else {
                ir_emit(f, OP_RET)->ty = T_VOID;
            }
            break;
        }
        case NODE_PRINT: lower_print(f, n); break;
        case NODE_BREAK: ir_emit(f, OP_BR)->t1 = ir_brk; break;
        case NODE_CONTINUE: ir_emit(f, OP_BR)->t1 = ir_cont; break;
        case NODE_SWITCH: {
            ASTNode **arms = n->data.switch_node.arms;
            int na = n->data.switch_node.narms;
            V v = lower_expr(f, n->data.switch_node.expr);
            B *end = ir_newblock(f, "sw.e");
            B *alab[64];
            if (na > 64) die("too many switch arms", n->line);
            int defidx = -1;
            for (int k = 0; k < na; k++) {
                alab[k] = ir_newblock(f, "sw.a");
                if (arms[k]->data.case_arm.is_default) defidx = k;
            }
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = end->id;
            B *chain = ir_newblock(f, "sw.c");
            ir_emit(f, OP_BR)->t1 = chain->id;
            for (int k = 0; k < na; k++) {
                f->cur = chain;
                if (!arms[k]->data.case_arm.is_default) {
                    V c = ir_icmp(f, C_EQ, v, kconst(arms[k]->data.case_arm.val));
                    B *next = ir_newblock(f, "sw.c");
                    I *cbr = ir_emit(f, OP_CBR); cbr->a = c; cbr->t1 = alab[k]->id; cbr->t2 = next->id;
                    chain = next;
                }
            }
            f->cur = chain;
            ir_emit(f, OP_BR)->t1 = (defidx >= 0 ? alab[defidx] : end)->id;
            for (int k = 0; k < na; k++) {
                f->cur = alab[k];
                lower_stmt(f, arms[k]->data.case_arm.blk);
                if (!ir_terminated(f))
                    ir_emit(f, OP_BR)->t1 = (k + 1 < na ? alab[k + 1] : end)->id;
            }
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_EXTERN_FUNC: case NODE_EXTERN_GLOB: break;
        default: lower_expr(f, n); break;
    }
}

static F *ir_newfunc(const char *nm, int np, char **params) {
    F *fn = calloc(1, sizeof *fn);
    fn->nm = nm; fn->np = np; fn->params = params;
    if (ir_funcs) { F *p = ir_funcs; while (p->next) p = p->next; p->next = fn; }
    else ir_funcs = fn;
    return fn;
}

static const char *ir_bin_name(int sub) {
    static const char *nm[] = { "add", "sub", "mul", "sdiv", "srem", "and", "or", "xor", "shl", "sar" };
    return nm[sub];
}
static const char *ir_cmp_name(int sub) {
    static const char *nm[] = { "eq", "ne", "slt", "sle", "sgt", "sge" };
    return nm[sub];
}
static const char *ir_ty_name(ITy ty) {
    static const char *nm[] = { "i1", "i8", "i64", "ptr", "void" };
    return nm[ty];
}
static void ir_print_v(V v) {
    if (v.k == K_CONST) printf("%ld", v.c);
    else if (v.k == K_REG) printf("%%v%d", v.id);
    else if (v.k == K_GLOBAL) printf("@%s", v.nm);
    else if (v.k == K_FUNC) printf("@%s", v.nm);
    else if (v.k == K_LIT) printf("@%s", v.nm);
}
static void ir_print_blk(int id) {
    for (F *f = ir_funcs; f; f = f->next)
        for (B *b = f->blocks; b; b = b->next)
            if (b->id == id) { printf("label %%%s", b->nm); return; }
    printf("label %%L%d", id);
}

static void ir_print_fn(F *f) {
    printf("\nfunc @%s(", f->nm);
    for (int i = 0; i < f->np; i++) printf("%s%s", i ? ", " : "", f->params[i]);
    printf(") {\n");
    for (B *b = f->blocks; b; b = b->next) {
        printf("%s:\n", b->nm);
        for (I *in = b->head; in; in = in->next) {
                printf("  ");
                switch (in->op) {
                    case OP_BIN: printf("%%v%d = %s i64 ", in->dst, ir_bin_name(in->sub)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case OP_ICMP: printf("%%v%d = icmp %s i64 ", in->dst, ir_cmp_name(in->sub)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case OP_LOAD: printf("%%v%d = load %s, ", in->dst, ir_ty_name(in->ty)); ir_print_v(in->a); break;
                    case OP_STORE: printf("store %s ", ir_ty_name(in->ty)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case OP_ALLOCA: printf("%%v%d = alloca %s", in->dst, ir_ty_name(in->ty)); break;
                    case OP_CALL: printf("%%v%d = call i64 @%s(", in->dst, in->nm); for (int k = 0; k < in->nargs; k++) { if (k) printf(", "); ir_print_v(in->args[k]); } printf(")"); break;
                    case OP_BR: printf("br "); ir_print_blk(in->t1); break;
                    case OP_CBR: printf("cbr i1 "); ir_print_v(in->a); printf(", "); ir_print_blk(in->t1); printf(", "); ir_print_blk(in->t2); break;
                    case OP_RET: if (in->ty == T_VOID) printf("ret void"); else { printf("ret i64 "); ir_print_v(in->a); } break;
                    case OP_PRINT: printf("print %s ", in->sub ? "str" : "i64"); ir_print_v(in->a); break;
                    case OP_ZEXT: printf("%%v%d = zext i8 ", in->dst); ir_print_v(in->a); printf(" to i64"); break;
                    case OP_TRUNC: printf("%%v%d = trunc i64 ", in->dst); ir_print_v(in->a); printf(" to i8"); break;
                    case OP_GADDR: printf("%%v%d = global.addr @%s", in->dst, in->nm); break;
                    case OP_PTRADD: printf("%%v%d = ptradd ", in->dst); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case OP_SYSCALL: printf("%%v%d = syscall(", in->dst); for (int k = 0; k < in->nargs; k++) { if (k) printf(", "); ir_print_v(in->args[k]); } printf(")"); break;
                    case OP_COPY: printf("%%v%d = copy ", in->dst); ir_print_v(in->a); break;
                    case OP_PHI:
                        printf("%%v%d = phi i64 [ ", in->dst);
                        for (int k = 0; k < in->nargs; k++) {
                            if (k) printf(", ");
                            ir_print_v(in->args[k]);
                            printf(", ");
                            ir_print_blk(in->ppred[k]);
                        }
                        printf(" ]");
                        break;
                    default: break;
                }
                printf("\n");
            }
        }
        printf("}\n");
}

static void ir_print(void) {
    for (int i = 0; i < ir_nstr; i++) {
        printf("@.str%d = c\"", i);
        for (int j = 0; j < ir_strs[i].len; j++) {
            char c = ir_strs[i].data[j];
            if (c == '\n') printf("\\0A");
            else if (c < 32 || c > 126) printf("\\%02X", (unsigned char)c);
            else putchar(c);
        }
        printf("\"\n");
    }
    for (int i = 0; i < ir_nglob; i++) {
        printf("@%s = global %s", ir_globals[i].nm, ir_ty_name(ir_globals[i].ty));
        if (ir_globals[i].has_init) printf(" %ld", ir_globals[i].init);
        printf("\n");
    }
    for (F *f = ir_funcs; f; f = f->next) ir_print_fn(f);
}

static void ir_lower_function(ASTNode *n) {
    F *f = ir_newfunc(n->data.function.name, n->data.function.pcount, n->data.function.params);
    B *entry = ir_newblock(f, "entry");
    f->cur = entry;
    ir_symn = 0;
    for (int i = 0; i < n->data.function.pcount; i++) {
        V param = kreg(ir_nreg++);
        V p = ir_alloca(f, T_I64, 8);
        ir_store(f, T_I64, param, p);
        if (i < 16) f->preg[i] = param.id;
        ir_bind(n->data.function.params[i], p, T_I64, &TY_INT);
    }
    lower_stmt(f, n->data.function.body);
    if (!ir_terminated(f)) {
        I *in = ir_emit(f, OP_RET); in->ty = T_VOID;
    }
    ir_symn = 0;
}

static void ir_lower_program(ASTNode *root) {
    ir_funcs = NULL; ir_nreg = 1; ir_nblk = 0; ir_nglob = 0; ir_nstr = 0;
    nfn = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) {
            ir_globals[ir_nglob].nm = n->data.let.name;
            ir_globals[ir_nglob].ty = ir_ty(n->data.let.ty);
            ir_globals[ir_nglob].gast = n->data.let.ty;
            ir_globals[ir_nglob].has_init = 0;
            ir_nglob++;
        } else if (n->type == NODE_FUNCTION) {
            if (nfn >= (int)(sizeof FNS / sizeof *FNS)) die("too many functions", n->line);
            FNS[nfn++] = (typeof(FNS[0])){ n->data.function.name, 0, n->data.function.pcount };
        }
    }
    fn_hash_build();
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION) ir_lower_function(n);
    }
    F *entry = ir_newfunc("entry", 0, NULL);
    B *eb = ir_newblock(entry, "entry");
    entry->cur = eb;
    ir_symn = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION || n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
        if (n->type == NODE_LET) {
            if (!n->data.let.value) continue;
            for (int g = 0; g < ir_nglob; g++) {
                if (!strcmp(ir_globals[g].nm, n->data.let.name)) {
                    V v = lower_expr(entry, n->data.let.value);
                    if (ir_globals[g].ty == T_I8) v = ir_trunc(entry, v);
                    V p = ir_gaddr(entry, n->data.let.name);
                    ir_store(entry, ir_globals[g].ty, v, p);
                    break;
                }
            }
        } else {
            lower_stmt(entry, n);
        }
    }
    I *ret = ir_emit(entry, OP_RET); ret->ty = T_VOID;
    ir_symn = 0;
}

#define IRBLK 1024
static B *cg_b[IRBLK];
static int cg_np[IRBLK], cg_ns[IRBLK], cg_p[IRBLK][6], cg_s[IRBLK][2], cg_n;
static int cg_reach[IRBLK], cg_idom[IRBLK], cg_ndf[IRBLK], cg_df[IRBLK][16];
static int cg_children[IRBLK][IRBLK], cg_nch[IRBLK];
static uint64_t cg_dom[IRBLK][IRBLK / 64];
static int id2x[65536];

static void ir_cfg(F *f) {
    cg_n = 0;
    for (B *b = f->blocks; b; b = b->next) {
        if (cg_n >= IRBLK) die("too many blocks", 0);
        id2x[b->id] = cg_n; cg_b[cg_n++] = b;
    }
    for (int i = 0; i < cg_n; i++) { cg_np[i] = 0; cg_ns[i] = 0; }
    for (int i = 0; i < cg_n; i++) {
        B *b = cg_b[i];
        if (!b->tail) continue;
        if (b->tail->op == OP_BR) cg_s[i][cg_ns[i]++] = id2x[b->tail->t1];
        else if (b->tail->op == OP_CBR) {
            cg_s[i][cg_ns[i]++] = id2x[b->tail->t1];
            cg_s[i][cg_ns[i]++] = id2x[b->tail->t2];
        }
    }
    for (int i = 0; i < cg_n; i++)
        for (int j = 0; j < cg_ns[i]; j++) {
            int t = cg_s[i][j];
            if (cg_np[t] >= 6) die("too many predecessors", 0);
            cg_p[t][cg_np[t]++] = i;
        }
}

static void ir_split_edges(F *f) {
    ir_cfg(f);
    struct { I *in; int t; } spl[512];
    int ns = 0;
    for (int i = 0; i < cg_n; i++) {
        if (cg_ns[i] != 2) continue;
        for (int j = 0; j < 2; j++) {
            int t = cg_s[i][j];
            if (cg_np[t] > 1 && ns < 512) { spl[ns].in = cg_b[i]->tail; spl[ns].t = t; ns++; }
        }
    }
    for (int k = 0; k < ns; k++) {
        B *m = ir_newblock(f, "split");
        f->cur = m;
        I *br = ir_emit(f, OP_BR);
        br->t1 = spl[k].t;
        if (spl[k].in->t1 == spl[k].t) spl[k].in->t1 = m->id;
        else spl[k].in->t2 = m->id;
    }
}

static void ir_prune(F *f) {
    ir_cfg(f);
    for (int i = 0; i < cg_n; i++) cg_reach[i] = 0;
    int stk[IRBLK], sp = 0;
    if (cg_n) { stk[sp++] = 0; cg_reach[0] = 1; }
    while (sp) {
        int i = stk[--sp];
        for (int j = 0; j < cg_ns[i]; j++) {
            int t = cg_s[i][j];
            if (!cg_reach[t]) { cg_reach[t] = 1; stk[sp++] = t; }
        }
    }
    B **pp = &f->blocks;
    while (*pp) {
        B *b = *pp;
        if (!cg_reach[id2x[b->id]]) *pp = b->next;
        else pp = &b->next;
    }
    ir_cfg(f);
    for (B *b = f->blocks; b; b = b->next) {
        for (I *in = b->head; in && in->op == OP_PHI; in = in->next) {
            int w = 0;
            for (int k = 0; k < in->nargs; k++) {
                int px = id2x[in->ppred[k]];
                int keep = px >= 0 && px < cg_n && cg_b[px] && cg_b[px]->id == in->ppred[k] && cg_reach[px];
                for (int j = 0; keep && j < cg_np[px]; j++)
                    if (cg_s[px][j] == id2x[b->id]) { keep = 2; break; }
                if (keep == 2) { in->args[w] = in->args[k]; in->ppred[w] = in->ppred[k]; w++; }
            }
            in->nargs = w;
        }
    }
}

static void ir_dominators(void) {
    int nw = (cg_n + 63) / 64;
    for (int i = 0; i < cg_n; i++) {
        if (!cg_reach[i]) { memset(cg_dom[i], 0, sizeof(uint64_t) * nw); continue; }
        if (i == 0) { memset(cg_dom[i], 0, sizeof(uint64_t) * nw); cg_dom[i][0] = 1; }
        else for (int w = 0; w < nw; w++) cg_dom[i][w] = ~0ULL;
    }
    for (int iter = 0; iter < cg_n + 2; iter++) {
        int changed = 0;
        for (int i = 1; i < cg_n; i++) {
            if (!cg_reach[i]) continue;
            uint64_t nb[IRBLK / 64];
            for (int w = 0; w < nw; w++) nb[w] = ~0ULL;
            int any = 0;
            for (int j = 0; j < cg_np[i]; j++) {
                int p = cg_p[i][j];
                if (!cg_reach[p]) continue;
                for (int w = 0; w < nw; w++) nb[w] &= cg_dom[p][w];
                any = 1;
            }
            if (!any) for (int w = 0; w < nw; w++) nb[w] = 0;
            nb[i / 64] |= 1ULL << (i % 64);
            for (int w = 0; w < nw; w++)
                if (nb[w] != cg_dom[i][w]) { cg_dom[i][w] = nb[w]; changed = 1; }
        }
        if (!changed) break;
    }
    for (int i = 0; i < cg_n; i++) cg_idom[i] = -1;
    cg_idom[0] = 0;
    for (int i = 1; i < cg_n; i++) {
        if (!cg_reach[i]) continue;
        for (int d = 0; d < cg_n; d++) {
            if (d == i || !cg_reach[d]) continue;
            if (!(cg_dom[i][d / 64] >> (d % 64) & 1)) continue;
            int same = 1;
            for (int w = 0; w < (cg_n + 63) / 64 && same; w++) {
                uint64_t x = cg_dom[i][w], y = cg_dom[d][w];
                if (i / 64 == w) x &= ~(1ULL << (i % 64));
                if (x != y) same = 0;
            }
            if (same) { cg_idom[i] = d; break; }
        }
    }
    for (int i = 0; i < cg_n; i++) { cg_nch[i] = 0; cg_ndf[i] = 0; }
    for (int i = 1; i < cg_n; i++)
        if (cg_reach[i] && cg_idom[i] >= 0) cg_children[cg_idom[i]][cg_nch[cg_idom[i]]++] = i;
    for (int i = 0; i < cg_n; i++) {
        if (!cg_reach[i] || cg_np[i] < 2) continue;
        for (int j = 0; j < cg_np[i]; j++) {
            int runner = cg_p[i][j];
            while (runner != cg_idom[i]) {
                if (cg_ndf[runner] < 16) cg_df[runner][cg_ndf[runner]++] = i;
                if (runner == 0) break;
                runner = cg_idom[runner];
            }
        }
    }
}

static void ir_unlink_dead(F *f) {
    for (B *b = f->blocks; b; b = b->next) {
        I *prev = NULL, *in = b->head;
        while (in) {
            I *nx = in->next;
            if (in->op == OP_DEAD) {
                if (prev) prev->next = nx; else b->head = nx;
                if (b->tail == in) b->tail = prev;
            } else prev = in;
            in = nx;
        }
    }
}

static void ir_insert_before_tail(B *b, I *in) {
    if (!b->head) { b->head = b->tail = in; return; }
    if (b->head == b->tail) { in->next = b->tail; b->head = in; return; }
    I *p = b->head;
    while (p->next != b->tail) p = p->next;
    in->next = b->tail; p->next = in;
}

static V dmap_val[65536];
static unsigned char dmap_ok[65536];

static V ir_rd(V v) {
    while (v.k == K_REG && dmap_ok[v.id]) v = dmap_val[v.id];
    return v;
}

static void ir_rewrite_ops(I *in) {
    in->a = ir_rd(in->a);
    in->b = ir_rd(in->b);
    for (int k = 0; k < in->nargs; k++) in->args[k] = ir_rd(in->args[k]);
}

static void ir_mem2reg(F *f) {
    ir_cfg(f);
    ir_dominators();
    I *allocas[512];
    int na = 0;
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next)
            if (in->op == OP_ALLOCA) {
                if (na >= 512) die("too many allocas", 0);
                allocas[na++] = in;
            }
    int amap[65536];
    for (int i = 0; i < 65536; i++) amap[i] = -1;
    for (int i = 0; i < na; i++) amap[allocas[i]->dst] = i;

    static V stk[512][512];
    static int sp[512], cap[512];
    static unsigned char promoted[512];
    for (int i = 0; i < na; i++) { sp[i] = 0; cap[i] = 8; promoted[i] = 0; }

    for (int ai = 0; ai < na; ai++) {
        I *A = allocas[ai];
        int ok = 1;
        for (B *b = f->blocks; b && ok; b = b->next)
            for (I *in = b->head; in && ok; in = in->next) {
                if (in == A) continue;
                int ua = in->a.k == K_REG && in->a.id == A->dst;
                int ub = in->b.k == K_REG && in->b.id == A->dst;
                if (in->op == OP_LOAD && ua) continue;
                if (in->op == OP_STORE && ub) continue;
                if (ua || ub) ok = 0;
                for (int k = 0; k < in->nargs; k++)
                    if (in->args[k].k == K_REG && in->args[k].id == A->dst) ok = 0;
            }
        if (!ok) continue;
        promoted[ai] = 1;
        for (B *b = f->blocks; b; b = b->next)
            for (I *in = b->head; in; in = in->next)
                if (in->op == OP_STORE && in->b.k == K_REG && in->b.id == A->dst) cap[ai]++;
        unsigned char hasphi[IRBLK];
        memset(hasphi, 0, sizeof hasphi);
        unsigned char inwf[IRBLK];
        memset(inwf, 0, sizeof inwf);
        int wlist[IRBLK], wsp = 0;
        for (B *b = f->blocks; b; b = b->next)
            for (I *in = b->head; in; in = in->next)
                if (in->op == OP_STORE && in->b.k == K_REG && in->b.id == A->dst) {
                    int bi = id2x[b->id];
                    if (!inwf[bi]) { inwf[bi] = 1; wlist[wsp++] = bi; }
                }
        while (wsp) {
            int x = wlist[--wsp];
            for (int j = 0; j < cg_ndf[x]; j++) {
                int y = cg_df[x][j];
                if (hasphi[y]) continue;
                hasphi[y] = 1;
                I *phi = calloc(1, sizeof *phi);
                phi->op = OP_PHI; phi->ty = A->ty;
                phi->dst = ir_nreg++;
                phi->b = kreg(A->dst);
                phi->nargs = cg_np[y];
                phi->args = malloc(sizeof(V) * cg_np[y]);
                phi->ppred = malloc(sizeof(int) * cg_np[y]);
                for (int k = 0; k < cg_np[y]; k++) { phi->args[k] = kconst(0); phi->ppred[k] = cg_b[cg_p[y][k]]->id; }
                B *yb = cg_b[y];
                phi->next = yb->head;
                yb->head = phi;
                if (!yb->tail) yb->tail = phi;
                if (!inwf[y]) { inwf[y] = 1; wlist[wsp++] = y; }
            }
        }
    }

    for (int i = 0; i < 65536; i++) dmap_ok[i] = 0;

    int pidx[512];

    void rename(int bi) {
        for (int ai = 0; ai < na; ai++) pidx[ai] = sp[ai];
        B *b = cg_b[bi];
        for (I *in = b->head; in && in->op == OP_PHI; in = in->next) {
            int ai = amap[in->b.id];
            if (ai >= 0 && promoted[ai]) {
                if (sp[ai] >= cap[ai]) die("alloca stack overflow", 0);
                stk[ai][sp[ai]++] = kreg(in->dst);
            }
        }
        for (I *in = b->head; in; in = in->next) {
            if (in->op == OP_STORE && in->b.k == K_REG && amap[in->b.id] >= 0 && promoted[amap[in->b.id]]) {
                int ai = amap[in->b.id];
                if (sp[ai] >= cap[ai]) die("alloca stack overflow", 0);
                stk[ai][sp[ai]++] = ir_rd(in->a);
                in->op = OP_DEAD;
                continue;
            }
            if (in->op == OP_LOAD && in->a.k == K_REG && amap[in->a.id] >= 0 && promoted[amap[in->a.id]]) {
                int ai = amap[in->a.id];
                dmap_val[in->dst] = sp[ai] ? stk[ai][sp[ai] - 1] : kconst(0);
                dmap_ok[in->dst] = 1;
                in->op = OP_DEAD;
                continue;
            }
            ir_rewrite_ops(in);
        }
        for (int j = 0; j < cg_ns[bi]; j++) {
            int s = cg_s[bi][j];
            B *sb = cg_b[s];
            for (I *in = sb->head; in && in->op == OP_PHI; in = in->next) {
                int ai = amap[in->b.id];
                if (ai < 0 || !promoted[ai]) continue;
                for (int k = 0; k < in->nargs; k++)
                    if (in->ppred[k] == b->id) {
                        in->args[k] = sp[ai] ? stk[ai][sp[ai] - 1] : kconst(0);
                        break;
                    }
            }
        }
        for (int c = 0; c < cg_nch[bi]; c++) rename(cg_children[bi][c]);
        for (int ai = 0; ai < na; ai++) sp[ai] = pidx[ai];
    }
    if (cg_n) rename(0);
    ir_unlink_dead(f);
    ir_cfg(f);
}

static void ir_ssa_apply_reps(F *f) {
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next)
            ir_rewrite_ops(in);
}

static void ir_ssa_fold(F *f) {
    for (int iter = 0; iter < 16; iter++) {
        int changed = 0;
        for (int i = 0; i < 65536; i++) dmap_ok[i] = 0;
        for (B *b = f->blocks; b; b = b->next) {
            for (I *in = b->head; in; in = in->next) {
                if (in->op == OP_BIN && in->a.k == K_CONST && in->b.k == K_CONST) {
                    long x = in->a.c, y = in->b.c, r = 0;
                    int fold = 1;
                    switch (in->sub) {
                        case B_ADD: r = x + y; break;
                        case B_SUB: r = x - y; break;
                        case B_MUL: r = x * y; break;
                        case B_SDIV: if (!y) fold = 0; else r = x / y; break;
                        case B_SREM: if (!y) fold = 0; else r = x % y; break;
                        case B_AND: r = x & y; break;
                        case B_OR: r = x | y; break;
                        case B_XOR: r = x ^ y; break;
                        case B_SHL: r = x << (y & 63); break;
                        case B_SAR: r = x >> (y & 63); break;
                    }
                    if (fold) { dmap_val[in->dst] = kconst(r); dmap_ok[in->dst] = 1; in->op = OP_DEAD; changed = 1; continue; }
                }
                if (in->op == OP_ICMP && in->a.k == K_CONST && in->b.k == K_CONST) {
                    long x = in->a.c, y = in->b.c, r = 0;
                    switch (in->sub) {
                        case C_EQ: r = x == y; break;
                        case C_NE: r = x != y; break;
                        case C_SLT: r = x < y; break;
                        case C_SLE: r = x <= y; break;
                        case C_SGT: r = x > y; break;
                        case C_SGE: r = x >= y; break;
                    }
                    dmap_val[in->dst] = kconst(r); dmap_ok[in->dst] = 1;
                    in->op = OP_DEAD; changed = 1; continue;
                }
                if ((in->op == OP_ZEXT || in->op == OP_TRUNC) && in->a.k == K_CONST) {
                    dmap_val[in->dst] = kconst(in->a.c & 0xFF); dmap_ok[in->dst] = 1;
                    in->op = OP_DEAD; changed = 1; continue;
                }
                if (in->op == OP_CBR && in->a.k == K_CONST) {
                    in->op = OP_BR;
                    if (!in->a.c) in->t1 = in->t2;
                    changed = 1; continue;
                }
                if (in->op == OP_PHI) {
                    V same = kconst(0); int found = 0, allsame = 1;
                    for (int k = 0; k < in->nargs; k++) {
                        V v = in->args[k];
                        if (v.k == K_REG && v.id == in->dst) continue;
                        if (!found) { same = v; found = 1; }
                        else if (v.k != same.k || v.c != same.c || v.id != same.id) allsame = 0;
                    }
                    if (found && allsame) {
                        dmap_val[in->dst] = same; dmap_ok[in->dst] = 1;
                        in->op = OP_DEAD; changed = 1;
                    }
                    continue;
                }
            }
        }
        if (!changed) break;
        ir_ssa_apply_reps(f);
        ir_unlink_dead(f);
        ir_prune(f);
        for (B *b = f->blocks; b; b = b->next)
            for (I *in = b->head; in; in = in->next)
                if (in->op == OP_PHI && in->nargs == 0) in->op = OP_DEAD;
        ir_unlink_dead(f);
    }
}

static void ir_ssa_gvn(F *f) {
    static struct { int op, sub, ty; long ka, kb, va, vb; int dst; int depth; } tbl[8192];
    int nt = 0;
    struct { int reg; V to; } reps[8192];
    int nr = 0;
    int comm[11] = { 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0 };

    void enter(int bi, int depth) {
        for (I *in = cg_b[bi]->head; in; in = in->next) {
            if (in->op != OP_BIN && in->op != OP_ICMP && in->op != OP_ZEXT && in->op != OP_TRUNC && in->op != OP_PTRADD && in->op != OP_GADDR) continue;
            long ka, kb;
            ka = in->a.k == K_CONST ? (0x4000000000L + in->a.c) : (0x8000000000L + in->a.id);
            kb = in->b.k == K_CONST ? (0x4000000000L + in->b.c) : (0x8000000000L + in->b.id);
            if (in->a.k == K_LIT) ka = 0xC000000000L + in->a.c;
            if (in->b.k == K_LIT) kb = 0xC000000000L + in->b.c;
            if (in->op == OP_GADDR) { ka = 0xD000000000L; kb = (long)(size_t)in->nm; }
            if (in->op != OP_GADDR && comm[in->op == OP_BIN ? in->sub : 10] && ka > kb) { long t = ka; ka = kb; kb = t; }
            int hit = -1;
            for (int i = nt - 1; i >= 0; i--) {
                if (tbl[i].op == in->op && tbl[i].sub == in->sub && tbl[i].ty == in->ty && tbl[i].ka == ka && tbl[i].kb == kb) { hit = i; break; }
            }
            if (hit >= 0) {
                if (nr < 8192) { reps[nr].reg = in->dst; reps[nr].to = kreg(tbl[hit].dst); nr++; }
                in->op = OP_DEAD;
                continue;
            }
            if (nt < 8192) {
                tbl[nt].op = in->op; tbl[nt].sub = in->sub; tbl[nt].ty = in->ty;
                tbl[nt].ka = ka; tbl[nt].kb = kb; tbl[nt].dst = in->dst; tbl[nt].depth = depth;
                nt++;
            }
        }
        for (int c = 0; c < cg_nch[bi]; c++) enter(cg_children[bi][c], depth + 1);
        while (nt > 0 && tbl[nt - 1].depth >= depth) nt--;
    }
    for (int i = 0; i < 65536; i++) dmap_ok[i] = 0;
    if (cg_n) enter(0, 0);
    for (int i = 0; i < nr; i++) { dmap_val[reps[i].reg] = reps[i].to; dmap_ok[reps[i].reg] = 1; }
    ir_ssa_apply_reps(f);
    ir_unlink_dead(f);
}

static void ir_ssa_dce(F *f) {
    static I *imap[65536];
    for (int i = 0; i < 65536; i++) imap[i] = NULL;
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next)
            if (in->dst >= 0 && in->dst < 65536) imap[in->dst] = in;
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next) in->mk = 0;
    static I *wl[262144];
    int wsp = 0;
    #define IRMARK(x) do { I *_i = (x); if (_i && !_i->mk) { _i->mk = 1; wl[wsp++] = _i; } } while (0)
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next)
            if (in->op == OP_STORE || in->op == OP_CALL || in->op == OP_PRINT || in->op == OP_SYSCALL ||
                in->op == OP_RET || in->op == OP_BR || in->op == OP_CBR || in->op == OP_ALLOCA)
                IRMARK(in);
    while (wsp) {
        I *in = wl[--wsp];
        if (in->a.k == K_REG && imap[in->a.id]) IRMARK(imap[in->a.id]);
        if (in->b.k == K_REG && imap[in->b.id]) IRMARK(imap[in->b.id]);
        for (int k = 0; k < in->nargs; k++)
            if (in->args[k].k == K_REG && imap[in->args[k].id]) IRMARK(imap[in->args[k].id]);
    }
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next)
            if (!in->mk && in->op != OP_STORE && in->op != OP_CALL && in->op != OP_PRINT && in->op != OP_SYSCALL &&
                in->op != OP_RET && in->op != OP_BR && in->op != OP_CBR && in->op != OP_ALLOCA)
                in->op = OP_DEAD;
    ir_unlink_dead(f);
}

static void ir_out_of_ssa(F *f) {
    int any = 1;
    while (any) {
        any = 0;
        for (B *b = f->blocks; b; b = b->next) {
            if (!b->head || b->head->op != OP_PHI) continue;
            any = 1;
            I *phis[512];
            int np = 0;
            for (I *in = b->head; in && in->op == OP_PHI; in = in->next)
                if (np < 512) phis[np++] = in;
            for (int k = 0; k < np; k++) phis[k]->mk = ir_nreg++;
            for (int pass = 0; pass < 2; pass++) {
                for (int k = 0; k < np; k++) {
                    I *phi = phis[k];
                    for (int e = 0; e < phi->nargs; e++) {
                        B *pb = NULL;
                        for (B *bb = f->blocks; bb; bb = bb->next)
                            if (bb->id == phi->ppred[e]) { pb = bb; break; }
                        if (!pb) continue;
                        I *cp = calloc(1, sizeof *cp);
                        cp->op = OP_COPY; cp->dst = pass ? phi->dst : (int)phis[k]->mk;
                        cp->ty = phi->ty;
                        cp->a = pass ? kreg((int)phis[k]->mk) : phi->args[e];
                        ir_insert_before_tail(pb, cp);
                    }
                }
            }
            for (int k = 0; k < np; k++) phis[k]->op = OP_DEAD;
            break;
        }
    }
    ir_unlink_dead(f);
}

static void ir_opt_function(F *f) {
    int dump = getenv("LGC_DUMP_SSA") != NULL;
    ir_split_edges(f);
    ir_prune(f);
    if (dump) { printf("==== %s after split/prune ====\n", f->nm); ir_print_fn(f); }
    ir_mem2reg(f);
    if (dump) { printf("==== %s after mem2reg ====\n", f->nm); ir_print_fn(f); }
    ir_ssa_fold(f);
    if (dump) { printf("==== %s after fold ====\n", f->nm); ir_print_fn(f); }
    ir_ssa_gvn(f);
    if (dump) { printf("==== %s after gvn ====\n", f->nm); ir_print_fn(f); }
    ir_ssa_dce(f);
    if (dump) { printf("==== %s after dce ====\n", f->nm); ir_print_fn(f); }
}

static void ir_pipeline(ASTNode *root) {
    ir_lower_program(root);
    for (F *f = ir_funcs; f; f = f->next) ir_opt_function(f);
    for (F *f = ir_funcs; f; f = f->next) ir_out_of_ssa(f);
}

static void ir_ldv_rax(V v, long *off) {
    if (v.k == K_CONST) mov_rax_imm(v.c);
    else if (v.k == K_LIT) { EMIT(0x48, 0x8D, 0x05); emit_patch(1, (int)v.c); }
    else { EMIT(0x48, 0x8B); rbp_disp(0, (int)off[v.id]); }
}

static void ir_ldv_rcx(V v, long *off) {
    if (v.k == K_CONST) {
        if (v.c >= -2147483648LL && v.c <= 2147483647LL) { EMIT(0x48, 0xC7, 0xC1); emit_imm(v.c, 4); }
        else { EMIT(0x48, 0xB9); emit_imm(v.c, 8); }
    } else if (v.k == K_LIT) { EMIT(0x48, 0x8D, 0x0D); emit_patch(1, (int)v.c); }
    else { EMIT(0x48, 0x8B); rbp_disp(1, (int)off[v.id]); }
}

static void ir_st_rax(int dst, long *off) {
    EMIT(0x48, 0x89);
    rbp_disp(0, (int)off[dst]);
}

static int ir_exit_lab = -1;

static void ir_emit_fn(F *f, int is_entry) {
    int maxr = 1;
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next) {
            if (in->dst > maxr) maxr = in->dst;
            if (in->a.k == K_REG && in->a.id > maxr) maxr = in->a.id;
            if (in->b.k == K_REG && in->b.id > maxr) maxr = in->b.id;
            for (int k = 0; k < in->nargs; k++)
                if (in->args[k].k == K_REG && in->args[k].id > maxr) maxr = in->args[k].id;
        }
    long *off = calloc((size_t)maxr + 2, sizeof(long));
    long framesz = 0;
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next) {
            if (in->op == OP_ALLOCA && !off[in->dst]) {
                framesz += in->bytes ? in->bytes : 8;
                off[in->dst] = -framesz;
            }
        }
    for (B *b = f->blocks; b; b = b->next)
        for (I *in = b->head; in; in = in->next) {
            if (in->dst >= 0 && !off[in->dst] && in->op != OP_ALLOCA) {
                framesz += 8;
                off[in->dst] = -framesz;
            }
            if (in->a.k == K_REG && !off[in->a.id]) { framesz += 8; off[in->a.id] = -framesz; }
            if (in->b.k == K_REG && !off[in->b.id]) { framesz += 8; off[in->b.id] = -framesz; }
            for (int k = 0; k < in->nargs; k++)
                if (in->args[k].k == K_REG && !off[in->args[k].id]) { framesz += 8; off[in->args[k].id] = -framesz; }
        }
    framesz = (framesz + 15) & ~15L;
    int blab[IRBLK], nb = 0;
    for (B *b = f->blocks; b; b = b->next) blab[nb++] = new_label();
    int epilab = new_label();
    EMIT(0x55);
    EMIT(0x48, 0x89, 0xE5);
    if (framesz) { EMIT(0x48, 0x81, 0xEC); emit_imm(framesz, 4); }
    if (!is_entry) {
        static const int preg[6] = { 7, 6, 2, 1, 8, 9 };
        if (f->np > 6) die("IR backend supports at most 6 parameters", 0);
        for (int i = 0; i < f->np && i < 6; i++) {
            EMIT(preg[i] >= 8 ? 0x4C : 0x48, 0x89);
            rbp_disp(preg[i] & 7, (int)off[f->preg[i]]);
        }
    }
    int bi = 0;
    for (B *b = f->blocks; b; b = b->next, bi++) {
        put_label(blab[bi]);
        for (I *in = b->head; in; in = in->next) {
            switch (in->op) {
                case OP_BIN: {
                    ir_ldv_rax(in->a, off);
                    ir_ldv_rcx(in->b, off);
                    switch (in->sub) {
                        case B_ADD: EMIT(0x48, 0x01, 0xC8); break;
                        case B_SUB: EMIT(0x48, 0x29, 0xC8); break;
                        case B_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC1); break;
                        case B_AND: EMIT(0x48, 0x21, 0xC8); break;
                        case B_OR: EMIT(0x48, 0x09, 0xC8); break;
                        case B_XOR: EMIT(0x48, 0x31, 0xC8); break;
                        case B_SHL: EMIT(0x48, 0xD3, 0xE0); break;
                        case B_SAR: EMIT(0x48, 0xD3, 0xF8); break;
                        case B_SDIV: EMIT(0x48, 0x99); EMIT(0x48, 0xF7, 0xF9); break;
                        case B_SREM: EMIT(0x48, 0x99); EMIT(0x48, 0xF7, 0xF9); EMIT(0x48, 0x89, 0xD0); break;
                    }
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_ICMP: {
                    ir_ldv_rax(in->a, off);
                    ir_ldv_rcx(in->b, off);
                    EMIT(0x48, 0x39, 0xC8);
                    static const int cc[6] = { 0x94, 0x95, 0x9C, 0x9E, 0x9F, 0x9D };
                    EMIT(0x0F, cc[in->sub], 0xC0);
                    EMIT(0x0F, 0xB6, 0xC0);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_LOAD: {
                    ir_ldv_rax(in->a, off);
                    if (in->ty == T_I8) EMIT(0x0F, 0xB6, 0x00);
                    else EMIT(0x48, 0x8B, 0x00);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_STORE: {
                    ir_ldv_rax(in->a, off);
                    ir_ldv_rcx(in->b, off);
                    if (in->ty == T_I8) EMIT(0x88, 0x01);
                    else EMIT(0x48, 0x89, 0x01);
                    break;
                }
                case OP_ALLOCA: {
                    EMIT(0x48, 0x8D);
                    rbp_disp(0, (int)off[in->dst]);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_PTRADD: {
                    ir_ldv_rax(in->a, off);
                    ir_ldv_rcx(in->b, off);
                    EMIT(0x48, 0x01, 0xC8);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_COPY: {
                    ir_ldv_rax(in->a, off);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_ZEXT: case OP_TRUNC: {
                    ir_ldv_rax(in->a, off);
                    EMIT(0x0F, 0xB6, 0xC0);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_GADDR: {
                    Glob *g = glob_find(in->nm);
                    if (!g) die("undefined global", 0);
                    EMIT(0x48, 0x8D, 0x05);
                    emit_patch(2, g->off);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_CALL: {
                    static const int areg[6][2] = { {7,0},{6,0},{2,0},{1,0},{8,1},{9,1} };
                    if (in->nargs > 6) die("IR backend supports at most 6 arguments", 0);
                    for (int k = 0; k < in->nargs; k++) {
                        ir_ldv_rax(in->args[k], off);
                        if (areg[k][1]) EMIT(0x49, 0x89, (uint8_t)(0xC0 | (areg[k][0] & 7)));
                        else EMIT(0x48, 0x89, (uint8_t)(0xC0 | areg[k][0]));
                    }
                    int fi = fn_find(in->nm);
                    if (fi < 0) die("call to undefined function", 0);
                    EMIT(0xE8);
                    emit_patch(0, FNS[fi].lab);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_SYSCALL: {
                    if (in->nargs != 4) die("syscall(nr, a, b, c)", 0);
                    ir_ldv_rax(in->args[0], off);
                    static const int smv[3] = { 0xCF, 0xCE, 0xCA };
                    for (int k = 1; k < 4; k++) {
                        ir_ldv_rcx(in->args[k], off);
                        EMIT(0x48, 0x89, smv[k - 1]);
                    }
                    EMIT(0x0F, 0x05);
                    ir_st_rax(in->dst, off);
                    break;
                }
                case OP_PRINT: {
                    if (freestanding) die("print is unavailable in freestanding mode", 0);
                    ir_ldv_rax(in->a, off);
                    EMIT(0xE8);
                    emit_patch(0, in->sub ? printstrlab : printlab);
                    break;
                }
                case OP_BR: {
                    int t = 0, idx = 0;
                    for (B *bb = f->blocks; bb; bb = bb->next, idx++)
                        if (bb->id == in->t1) { t = idx; break; }
                    EMIT(0xE9);
                    emit_rel32(blab[t]);
                    break;
                }
                case OP_CBR: {
                    ir_ldv_rax(in->a, off);
                    EMIT(0x48, 0x85, 0xC0);
                    int tt1 = 0, tt2 = 0, idx = 0;
                    for (B *bb = f->blocks; bb; bb = bb->next, idx++) {
                        if (bb->id == in->t1) tt1 = idx;
                        if (bb->id == in->t2) tt2 = idx;
                    }
                    EMIT(0x0F, 0x84);
                    emit_rel32(blab[tt2]);
                    EMIT(0xE9);
                    emit_rel32(blab[tt1]);
                    break;
                }
                case OP_RET: {
                    if (is_entry) {
                        if (in->ty != T_VOID) ir_ldv_rax(in->a, off);
                        EMIT(0xE9);
                        emit_rel32(ir_exit_lab);
                        break;
                    }
                    if (in->ty != T_VOID) ir_ldv_rax(in->a, off);
                    EMIT(0xE9);
                    emit_rel32(epilab);
                    break;
                }
                default: break;
            }
        }
    }
    if (!is_entry) {
        put_label(epilab);
        EMIT(0xC9, 0xC3);
    }
    free(off);
}

static void emit_entry_ir(void) {
    if (!freestanding) {
        for (int i = 0; i < 8; i++) {
            char nm[8];
            sprintf(nm, "argv%d", i + 1);
            Glob *a = glob_find(nm);
            if (!a) continue;
            EMIT(0x48, 0x8B, 0x44, 0x24, (uint8_t)(0x10 + 8 * i));
            EMIT(0x48, 0x89, 0x05);
            emit_patch(2, a->off);
        }
    }
    F *fe = ir_funcs;
    while (fe && strcmp(fe->nm, "entry")) fe = fe->next;
    if (fe) {
        ir_exit_lab = new_label();
        ir_emit_fn(fe, 1);
        put_label(ir_exit_lab);
        ir_exit_lab = -1;
    }
    int mi = fn_find(entry_name ? entry_name : "main");
    if (mi >= 0) {
        EMIT(0xE8);
        emit_patch(0, FNS[mi].lab);
        if (freestanding) EMIT(0xEB, 0xFE);
        else if (is_pe) { EMIT(0x48, 0x89, 0xC1); emit_call_iat(2); }
        else { EMIT(0x48, 0x89, 0xC7); mov_rax_imm(60); EMIT(0x0F, 0x05); }
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
}

static void generate_code_ir(ASTNode *root) {
    bin_fmt = (fmt == FMT_BIN);
    if (bin_fmt) die("IR backend requires ELF or PE output", 0);
    clen = 0;
    nglob = 0; gsize = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        if (nglob >= (int)(sizeof GLOB / sizeof *GLOB)) die("too many globals", n->line);
        GLOB[nglob] = (typeof(GLOB[0])){ n->data.let.name, n->data.let.ty, gsize, 0 };
        gsize += ty_size(n->data.let.ty);
        nglob++;
    }
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *fd = root->data.block.stmts[i];
        if (fd->type != NODE_FUNCTION) continue;
        int fi = fn_find(fd->data.function.name);
        if (fi < 0) die("undefined function", fd->line);
        FNS[fi].lab = new_label();
    }
    glob_hash_build();
    fn_hash_build();
    if (!freestanding) {
        printlab = new_label(); put_label(printlab);
        if (is_pe) emit_print_pe(); else emit_print_elf();
        printstrlab = new_label(); put_label(printstrlab);
        if (is_pe) emit_print_str_pe(); else emit_print_str_elf();
    }
    litlab = new_label();
    for (int i = 0; i < root->data.block.count; i++) {
        ASTNode *fd = root->data.block.stmts[i];
        if (fd->type != NODE_FUNCTION) continue;
        F *ff = ir_funcs;
        while (ff && strcmp(ff->nm, fd->data.function.name)) ff = ff->next;
        if (!ff) die("missing IR function", fd->line);
        put_label(FNS[fn_find(fd->data.function.name)].lab);
        ir_emit_fn(ff, 0);
    }
    entry = clen;
    emit_entry_ir();
    put_label(litlab);
    if (nlit) { memcpy(code + clen, LIT, nlit); clen += nlit; }
    shrink_relayout();
    pcb = (PE_SECT + 15) & ~15;
    apply_patches();
}

static void reset_codegen_state(void) {
    clen = 0; entry = 0; nlab = 1; npatch = 0; niat = 0;
    nglob = 0; gsize = 0; nfn = 0;
    memset(lab_pos, 0, sizeof lab_pos);
    memset(GLOB, 0, sizeof GLOB);
    memset(FNS, 0, sizeof FNS);
    memset(PATCH, 0, sizeof PATCH);
    for (int i = 0; i < HSZ; i++) { GH[i] = -1; FH[i] = -1; }
    litlab = 0; printlab = 0; printstrlab = 0; pcb = 0;
}

int main(int argc, char **argv) {
    int cli_fmt = -1, cli_free = -1, cli_emit_ir = 0, cli_backend = 0, ai = 1;
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
        else if (!strcmp(a, "--emit-ir")) cli_emit_ir = 1;
        else if (!strcmp(a, "--emit-ssa")) cli_emit_ir = 2;
        else if (!strcmp(a, "--backend=legacy")) cli_backend = 0;
        else if (!strcmp(a, "--backend=ssa")) cli_backend = 1;
        else if (!strcmp(a, "--backend=both")) cli_backend = 2;
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

    if (cli_emit_ir == 1) { ir_lower_program(root); ir_print(); return 0; }
    if (cli_emit_ir == 2) {
        ir_lower_program(root);
        for (F *f = ir_funcs; f; f = f->next) { ir_split_edges(f); ir_prune(f); ir_mem2reg(f); }
        ir_print();
        return 0;
    }

    if (cli_fmt >= 0) fmt = cli_fmt;
    if (cli_base >= 0) load_base = cli_base;
    if (cli_entry) entry_name = cli_entry;
    if (cli_free >= 0) freestanding = cli_free;
    if (raw_mode) { fmt = FMT_BIN; freestanding = 1; }
    if (boot_mode) { fmt = FMT_BIN; freestanding = 1; load_base = 0x100000; }
    if (fmt == FMT_BIN) freestanding = 1;
    is_pe = fmt == FMT_PE;

    if (!raw_mode && !getenv("LGC_NO_OPT")) optimize_program(root);

    if (cli_backend == 2) {
        generate_code(root);
        if (fmt == FMT_BIN) write_bin(out);
        else if (is_pe) write_pe(out);
        else write_elf(out);
        reset_codegen_state();
    }
    if (cli_backend >= 1) {
        char out2[512];
        if (fmt == FMT_BIN) die("IR backend requires ELF or PE output", 0);
        ir_pipeline(root);
        generate_code_ir(root);
        if (cli_backend == 2) {
            snprintf(out2, sizeof out2, "%s.ssa", out);
            if (is_pe) write_pe(out2); else write_elf(out2);
            printf("Generated %s (SSA IR backend)\n", out2);
        } else {
            if (is_pe) write_pe(out); else write_elf(out);
        }
    } else if (cli_backend == 0) {
        generate_code(root);
        if (fmt == FMT_BIN) write_bin(out);
        else if (is_pe) write_pe(out);
        else write_elf(out);
    }

    printf("Generated %s (%s x86-64)\n", out,
           fmt == FMT_BIN ? "flat binary" : is_pe ? "PE32+" : "ELF");
    return 0;
}

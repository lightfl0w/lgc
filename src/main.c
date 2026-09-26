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

#define LEX_STR_CAP (1 << 20)
static char LEX_STRPOOL[LEX_STR_CAP];
static int lex_str_n;
static char *lex_intern(const char *s, int len) {
    if (lex_str_n + len + 1 > LEX_STR_CAP) die("source too large", 0);
    char *p = LEX_STRPOOL + lex_str_n;
    lex_str_n += len + 1;
    memcpy(p, s, len);
    p[len] = 0;
    return p;
}

static unsigned lex_hash(const char *s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}
#define SYM_HASH_SIZE 128

#define PUSH(arr, n, cap, item) do {                                     \
    if ((n) >= (cap)) {                                                  \
        (cap) = (cap) ? (cap) * 2 : 4;                                   \
        (arr) = realloc((arr), (cap) * sizeof *(arr));                   \
    }                                                                    \
    (arr)[(n)++] = (item);                                               \
} while (0)

enum TOKEN_TYPE {
    TOK_LET, TOK_PRINT, TOK_IF, TOK_ELSE, TOK_WHILE, TOK_RETURN, TOK_FUNC,
    TOK_SIZEOF, TOK_INT, TOK_CHAR, TOK_CONST, TOK_BREAK, TOK_CONTINUE, TOK_EXTERN,
    TOK_FOR, TOK_SWITCH, TOK_CASE, TOK_DEFAULT, TOK_STRUCT, TOK_ENUM, TOK_IN, TOK_NAKED,
    TOK_DOT, TOK_ARROW, TOK_DOTDOT,
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
};

struct TOKEN { enum TOKEN_TYPE type; char *text; int line; };
struct LEX_STATE { const char *src; int pos, line; };

static struct TOKEN lex_make_token(enum TOKEN_TYPE t, const char *s, int len, int line) {
    struct TOKEN tk = { t, lex_intern(s, len), line };
    return tk;
}

static const char *LEX_KEYWORDS[] = { "let", "print", "if", "else", "while", "return", "func", "sizeof", "int", "char", "const", "break", "continue", "extern", "for", "switch", "case", "default", "struct", "enum", "in", "naked" };

static const uint64_t LEX_PUNCT_BIT[2] = {
    (1ULL << 33) | (1ULL << 37) | (1ULL << 38) | (1ULL << 40) | (1ULL << 41) | (1ULL << 42) | (1ULL << 43) |
    (1ULL << 44) | (1ULL << 45) | (1ULL << 47) | (1ULL << 58) | (1ULL << 59) |
    (1ULL << 60) | (1ULL << 61) | (1ULL << 62),
    (1ULL << 27) | (1ULL << 29) | (1ULL << 30) | (1ULL << 59) | (1ULL << 60) | (1ULL << 61) | (1ULL << 62) |
    (1ULL << 0),
};

static const uint64_t LEX_PAIR_BIT[2] = {
    (1ULL << 33) | (1ULL << 37) | (1ULL << 42) | (1ULL << 43) | (1ULL << 45) |
    (1ULL << 47) | (1ULL << 60) | (1ULL << 61) | (1ULL << 62), 0,
};

static const enum TOKEN_TYPE LEX_CHAR_TOK[128] = {
    ['+'] = TOK_PLUS, ['-'] = TOK_MINUS, ['*'] = TOK_STAR, ['/'] = TOK_SLASH,
    ['&'] = TOK_AMP, ['%'] = TOK_PERCENT,
    ['['] = TOK_LBRACKET, [']'] = TOK_RBRACKET,
    [';'] = TOK_SEMICOLON, [','] = TOK_COMMA, [':'] = TOK_COLON,
    ['('] = TOK_LPAREN, [')'] = TOK_RPAREN, ['{'] = TOK_LBRACE, ['}'] = TOK_RBRACE,
    ['='] = TOK_ASSIGN, ['!'] = TOK_NOT, ['<'] = TOK_LT, ['>'] = TOK_GT,
    ['|'] = TOK_PIPE, ['^'] = TOK_CARET, ['~'] = TOK_TILDE, ['@'] = TOK_AT,
};

static const enum TOKEN_TYPE LEX_PAIR2_TOK[128] = {
    ['='] = TOK_EQ, ['!'] = TOK_NE, ['<'] = TOK_LE, ['>'] = TOK_GE,
    ['+'] = TOK_PLUS_EQ, ['-'] = TOK_MINUS_EQ, ['*'] = TOK_STAR_EQ,
    ['/'] = TOK_SLASH_EQ, ['%'] = TOK_PERCENT_EQ,
};

static struct TOKEN lex_next_token(struct LEX_STATE *lx) {
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
    if (!c) return lex_make_token(TOK_EOF, "", 0, line);
    if (isalpha(c) || c == '_') {
        while (isalnum(lx->src[lx->pos]) || lx->src[lx->pos] == '_') lx->pos++;
        int len = lx->pos - s;
        for (int i = 0; i < (int)(sizeof LEX_KEYWORDS / sizeof *LEX_KEYWORDS); i++)
            if (len == (int)strlen(LEX_KEYWORDS[i]) && !memcmp(&lx->src[s], LEX_KEYWORDS[i], len))
                return lex_make_token(TOK_LET + i, &lx->src[s], len, line);
        return lex_make_token(TOK_IDENTIFIER, &lx->src[s], len, line);
    }
    if (isdigit(c)) {
        if (c == '0' && (lx->src[s + 1] == 'x' || lx->src[s + 1] == 'X')) {
            lx->pos = s + 2;
            while (isxdigit(lx->src[lx->pos])) lx->pos++;
        } else
            while (isdigit(lx->src[lx->pos])) lx->pos++;
        return lex_make_token(TOK_NUMBER, &lx->src[s], lx->pos - s, line);
    }
    if (c == '"') {
        lx->pos++;
        while (lx->src[lx->pos] && lx->src[lx->pos] != '"')
            lx->pos += lx->src[lx->pos] == '\\' && lx->src[lx->pos + 1] ? 2 : 1;
        if (lx->src[lx->pos] != '"') return lex_make_token(TOK_ERROR, &lx->src[s], 1, line);
        lx->pos++;
        return lex_make_token(TOK_STR, &lx->src[s], lx->pos - s, line);
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
            return lex_make_token(TOK_ERROR, &lx->src[s], 1, line);
        lx->pos += 2;
        char buf[16], rev[16];
        int n = 0;
        unsigned u = (unsigned)ch;
        do { buf[n++] = (char)('0' + u % 10); u /= 10; } while (u);
        for (int i = 0; i < n; i++) rev[i] = buf[n - 1 - i];
        struct TOKEN tk = { TOK_NUMBER, lex_intern(rev, n), line };
        return tk;
    }
    if (c == '&' && lx->src[s + 1] == '&') {
        lx->pos = s + 2;
        return lex_make_token(TOK_ANDAND, &lx->src[s], 2, line);
    }
    if (c == '|' && lx->src[s + 1] == '|') {
        lx->pos = s + 2;
        return lex_make_token(TOK_OROR, &lx->src[s], 2, line);
    }
    if ((c == '<' || c == '>') && lx->src[s + 1] == c) {
        lx->pos = s + 2;
        return lex_make_token(c == '<' ? TOK_SHL : TOK_SHR, &lx->src[s], 2, line);
    }
    if (c == '-' && lx->src[s + 1] == '>') {
        lx->pos = s + 2;
        return lex_make_token(TOK_ARROW, &lx->src[s], 2, line);
    }
    if (c == '.' && lx->src[s + 1] == '.') {
        lx->pos = s + 2;
        return lex_make_token(TOK_DOTDOT, &lx->src[s], 2, line);
    }
    if (c == '.') {
        lx->pos = s + 1;
        return lex_make_token(TOK_DOT, &lx->src[s], 1, line);
    }
    lx->pos++;
    unsigned char uc = (unsigned char)c;
    if (uc >= 128 || !(LEX_PUNCT_BIT[uc >> 6] >> (uc & 63) & 1))
        return lex_make_token(TOK_ERROR, &lx->src[s], 1, line);
    enum TOKEN_TYPE t = LEX_CHAR_TOK[uc];
    int len = 1;
    if (lx->src[lx->pos] == '=' && (LEX_PAIR_BIT[uc >> 6] >> (uc & 63) & 1)) {
        t = LEX_PAIR2_TOK[uc];
        len = 2;
        lx->pos++;
    }
    return lex_make_token(t, &lx->src[s], len, line);
}

enum NODE_KIND {
    NODE_NUMBER, NODE_VARIABLE, NODE_BINARY, NODE_LET, NODE_PRINT,
    NODE_BLOCK, NODE_IF, NODE_WHILE, NODE_RETURN, NODE_FUNCTION, NODE_CALL,
    NODE_ADDR, NODE_DEREF, NODE_INDEX, NODE_ASSIGN, NODE_SIZEOF, NODE_STR, NODE_NOT,
    NODE_BNOT, NODE_BREAK, NODE_CONTINUE, NODE_EXTERN_FUNC, NODE_EXTERN_GLOB,
    NODE_FOR, NODE_SWITCH, NODE_CASE, NODE_MEMBER, NODE_STRUCTDEF
};
enum BIN_OP { BIN_ADD, BIN_SUB, BIN_MUL, BIN_DIV, BIN_EQ, BIN_NE, BIN_LT, BIN_GT, BIN_LE, BIN_GE, BIN_MOD, BIN_AND, BIN_OR,
               BIN_BOR, BIN_BAND, BIN_BXOR, BIN_SHL, BIN_SHR };

struct TYPE { uint8_t kind; int len; uint8_t sz; struct TYPE *base; struct TYPE_FIELD *fields; int nfield; };
struct TYPE_FIELD { char *name; struct TYPE *ty; int off; };

static struct TYPE TYPE_INT = { 0, 0, 8, NULL }, TYPE_CHAR = { 0, 0, 1, NULL };
static struct TYPE *type_pointer(struct TYPE *b) {
    static struct TYPE t[512]; static int n;
    if (n >= (int)(sizeof t / sizeof *t)) die("too many types", 0);
    t[n] = (struct TYPE){ 1, 0, 8, b };
    return &t[n++];
}
static struct TYPE *type_array(int n, struct TYPE *b) {
    static struct TYPE t[512]; static int c;
    if (c >= (int)(sizeof t / sizeof *t)) die("too many types", 0);
    t[c] = (struct TYPE){ 2, n, 8, b };
    return &t[c++];
}
static int type_size(struct TYPE *t) { return t->kind == 2 ? t->len * type_size(t->base) : t->kind == 3 ? t->len : t->sz; }
static int type_is_char(struct TYPE *t) { return t->kind == 0 && t->sz == 1; }

#define TYPE_RECORD_MAX 128
#define TYPE_FIELD_MAX 1024
static struct { char *name; struct TYPE *ty; } TYPE_RECORDS[TYPE_RECORD_MAX]; static int type_nrecord;
static struct TYPE_FIELD TYPE_FIELD_POOL[TYPE_FIELD_MAX]; static int type_nfield;
static struct TYPE *type_record(void) {
    static struct TYPE t[256]; static int n;
    if (n >= (int)(sizeof t / sizeof *t)) die("too many structs", 0);
    t[n] = (struct TYPE){ 3, 0, 0, NULL, NULL, 0 };
    return &t[n++];
}
static struct TYPE *type_find_record(const char *name) {
    for (int i = 0; i < type_nrecord; i++) if (!strcmp(TYPE_RECORDS[i].name, name)) return TYPE_RECORDS[i].ty;
    return NULL;
}
static struct TYPE_FIELD *type_find_field(struct TYPE *st, const char *f) {
    for (int i = 0; i < st->nfield; i++) if (!strcmp(st->fields[i].name, f)) return &st->fields[i];
    return NULL;
}

struct AST_NODE {
    enum NODE_KIND type;
    int line;
    union {
        struct { long value; } number;
        struct { char *name; } variable;
        struct { enum BIN_OP op; struct AST_NODE *left, *right; } binary;
        struct { char *name; struct TYPE *ty; struct AST_NODE *value; } let;
        struct { struct AST_NODE **args; int ncount; } print;
        struct { struct AST_NODE **stmts; int count, cap; } block;
        struct { struct AST_NODE *cond, *then, *else_; } if_node;
        struct { struct AST_NODE *cond, *body; } while_node;
        struct { struct AST_NODE *value; } return_node;
        struct { char *name; char **params; struct TYPE **ptypes; int pcount; int naked; struct AST_NODE *body; } function;
        struct { char *name; struct AST_NODE **args; int acount; } call;
        struct { struct AST_NODE *value; } unary;
        struct { struct AST_NODE *base, *index; } index;
        struct { struct AST_NODE *lhs, *rhs; int cop; } assign;
        struct { char *name; int pcount; } extfn;
        struct { char *name; } extgl;
        struct { int off, len; } str;
        struct { struct AST_NODE *init, *cond, *inc, *body; } for_node;
        struct { struct AST_NODE *expr; struct AST_NODE **arms; int narms; } switch_node;
        struct { struct AST_NODE *base; char *field; int arrow; } member;
        struct { char *tag; struct AST_NODE *body; } structdef;
        struct { long val; int is_default; struct AST_NODE *blk; } case_arm;
    } data;
};

#define AST_CAP (1 << 18)
static struct AST_NODE AST_ARENA[AST_CAP];
static int ast_n;
static struct AST_NODE *ast_new(enum NODE_KIND t, int line) {
    if (ast_n >= AST_CAP) die("too many AST nodes", 0);
    struct AST_NODE *n = &AST_ARENA[ast_n++];
    memset(n, 0, sizeof *n);
    n->type = t; n->line = line;
    return n;
}

static struct AST_NODE *ast_binary(enum BIN_OP op, struct AST_NODE *l, struct AST_NODE *r, int line) {
    if (l->type == NODE_NUMBER && r->type == NODE_NUMBER) {
        long a = l->data.number.value, b = r->data.number.value, v = 0;
        switch (op) {
            case BIN_ADD: v = a + b; break;
            case BIN_SUB: v = a - b; break;
            case BIN_MUL: v = a * b; break;
            case BIN_DIV: if (!b) die("division by zero", line); v = a / b; break;
            case BIN_MOD: if (!b) die("modulo by zero", line); v = a % b; break;
            case BIN_EQ:  v = a == b; break;
            case BIN_NE:  v = a != b; break;
            case BIN_LT:  v = a < b; break;
            case BIN_GT:  v = a > b; break;
            case BIN_LE:  v = a <= b; break;
            case BIN_GE:  v = a >= b; break;
            case BIN_AND: v = a && b; break;
            case BIN_OR:  v = a || b; break;
            case BIN_BOR:  v = a | b; break;
            case BIN_BAND: v = a & b; break;
            case BIN_BXOR: v = a ^ b; break;
            case BIN_SHL:  v = a << (b & 63); break;
            case BIN_SHR:  v = a >> (b & 63); break;
        }
        struct AST_NODE *n = ast_new(NODE_NUMBER, line);
        n->data.number.value = v;
        return n;
    }
    struct AST_NODE *n = ast_new(NODE_BINARY, line);
    n->data.binary.op = op;
    n->data.binary.left = l;
    n->data.binary.right = r;
    return n;
}

static struct { char *name; long value; } SYM_CONSTS[256];
static int sym_nconst;
static int sym_const_find(const char *name) {
    for (int i = 0; i < sym_nconst; i++)
        if (!strcmp(SYM_CONSTS[i].name, name)) return i;
    return -1;
}

struct PARSE_STATE { struct TOKEN *tokens; int count, pos; struct TOKEN cur; };

static void parse_advance(struct PARSE_STATE *p) { p->cur = p->pos < p->count ? p->tokens[p->pos++] : (struct TOKEN){ TOK_EOF, NULL, 0 }; }

static void parse_expect(struct PARSE_STATE *p, enum TOKEN_TYPE t, const char *what) {
    if (p->cur.type != t) die(what, p->cur.line);
    parse_advance(p);
}

static long long lex_number(const char *s) {
    unsigned long long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        for (s += 2; *s; s++)
            v = v * 16 + (unsigned)(isdigit((unsigned char)*s) ? *s - '0' : (*s | 32) - 'a' + 10);
    } else
        for (; *s; s++) v = v * 10 + (unsigned)(*s - '0');
    return (long long)v;
}

static const uint16_t PARSE_BINOP[TOK_ERROR + 1] = {
    [TOK_EQ] = BIN_EQ | 6 << 5,  [TOK_NE] = BIN_NE | 6 << 5,
    [TOK_LT] = BIN_LT | 6 << 5,  [TOK_GT] = BIN_GT | 6 << 5,
    [TOK_LE] = BIN_LE | 6 << 5,  [TOK_GE] = BIN_GE | 6 << 5,
    [TOK_PLUS] = BIN_ADD | 9 << 5, [TOK_MINUS] = BIN_SUB | 9 << 5,
    [TOK_STAR] = BIN_MUL | 10 << 5, [TOK_SLASH] = BIN_DIV | 10 << 5,
    [TOK_PERCENT] = BIN_MOD | 10 << 5,
    [TOK_ANDAND] = BIN_AND | 2 << 5,
    [TOK_OROR] = BIN_OR | 1 << 5,
    [TOK_PIPE] = BIN_BOR | 3 << 5,
    [TOK_CARET] = BIN_BXOR | 4 << 5,
    [TOK_AMP] = BIN_BAND | 5 << 5,
    [TOK_SHL] = BIN_SHL | 8 << 5, [TOK_SHR] = BIN_SHR | 8 << 5,
};

static uint8_t PARSE_LITS[16384];
static int parse_nlit;

static struct AST_NODE *parse_expression(struct PARSE_STATE*);
static struct AST_NODE *parse_statement(struct PARSE_STATE*);
static struct AST_NODE *parse_block(struct PARSE_STATE*);

static struct TYPE *parse_type(struct PARSE_STATE *p) {
    struct TYPE *t;
    if (p->cur.type == TOK_STRUCT) {
        parse_advance(p);
        if (p->cur.type != TOK_IDENTIFIER) die("expected struct tag", p->cur.line);
        t = type_find_record(p->cur.text);
        if (!t) die("undefined struct type", p->cur.line);
        parse_advance(p);
    } else {
        if (p->cur.type != TOK_INT && p->cur.type != TOK_CHAR) die("expected type", p->cur.line);
        t = p->cur.type == TOK_CHAR ? &TYPE_CHAR : &TYPE_INT;
        parse_advance(p);
    }
    for (;;) {
        if (p->cur.type == TOK_STAR) { parse_advance(p); t = type_pointer(t); }
        else if (p->cur.type == TOK_LBRACKET) {
            parse_advance(p);
            if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
            int n = (int)lex_number(p->cur.text);
            parse_advance(p);
            parse_expect(p, TOK_RBRACKET, "expected ']'");
            t = type_array(n, t);
        } else break;
    }
    return t;
}

static struct AST_NODE *parse_primary(struct PARSE_STATE *p) {
    struct TOKEN t = p->cur;
    if (t.type == TOK_NUMBER) {
        parse_advance(p);
        struct AST_NODE *n = ast_new(NODE_NUMBER, t.line);
        n->data.number.value = lex_number(t.text);
        return n;
    }
    if (t.type == TOK_IDENTIFIER) {
        for (int i = 0; i < sym_nconst; i++)
            if (!strcmp(SYM_CONSTS[i].name, t.text)) {
                parse_advance(p);
                struct AST_NODE *n = ast_new(NODE_NUMBER, t.line);
                n->data.number.value = SYM_CONSTS[i].value;
                return n;
            }
        parse_advance(p);
        if (p->cur.type != TOK_LPAREN) {
            struct AST_NODE *n = ast_new(NODE_VARIABLE, t.line);
            n->data.variable.name = t.text;
            return n;
        }
        parse_advance(p);
        struct AST_NODE *n = ast_new(NODE_CALL, t.line);
        n->data.call.name = t.text;
        struct AST_NODE **args = NULL;
        int ac = 0, acap = 0;
        if (p->cur.type != TOK_RPAREN)
            do {
                PUSH(args, ac, acap, parse_expression(p));
            } while (p->cur.type == TOK_COMMA && (parse_advance(p), 1));
        parse_expect(p, TOK_RPAREN, "expected ')'");
        n->data.call.args = args;
        n->data.call.acount = ac;
        return n;
    }
    if (t.type == TOK_STR) {
        parse_advance(p);
        struct AST_NODE *n = ast_new(NODE_STR, t.line);
        n->data.str.off = parse_nlit;
        for (int i = 1; t.text[i] != '"'; i++) {
            char ch = t.text[i];
            if (ch == '\\') {
                ch = t.text[++i];
                ch = ch == 'n' ? '\n' : ch == 't' ? '\t' : ch;
            }
            if (parse_nlit >= (int)sizeof PARSE_LITS) die("string pool overflow", t.line);
            PARSE_LITS[parse_nlit++] = ch;
        }
        if (parse_nlit >= (int)sizeof PARSE_LITS) die("string pool overflow", t.line);
        PARSE_LITS[parse_nlit++] = 0;
        n->data.str.len = parse_nlit - n->data.str.off - 1;
        return n;
    }
    if (t.type == TOK_LPAREN) {
        parse_advance(p);
        struct AST_NODE *e = parse_expression(p);
        parse_expect(p, TOK_RPAREN, "expected ')'");
        return e;
    }
    die("syntax error", t.line);
    return NULL;
}

static struct AST_NODE *parse_postfix(struct PARSE_STATE *p) {
    struct AST_NODE *n = parse_primary(p);
    for (;;) {
        if (p->cur.type == TOK_LBRACKET) {
            int line = p->cur.line;
            parse_advance(p);
            struct AST_NODE *i = ast_new(NODE_INDEX, line);
            i->data.index.base = n;
            i->data.index.index = parse_expression(p);
            parse_expect(p, TOK_RBRACKET, "expected ']'");
            n = i;
        } else if (p->cur.type == TOK_DOT || p->cur.type == TOK_ARROW) {
            int line = p->cur.line, arrow = p->cur.type == TOK_ARROW;
            parse_advance(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected member name", p->cur.line);
            struct AST_NODE *m = ast_new(NODE_MEMBER, line);
            m->data.member.base = n;
            m->data.member.field = p->cur.text;
            m->data.member.arrow = arrow;
            parse_advance(p);
            n = m;
        } else break;
    }
    return n;
}

static struct AST_NODE *parse_unary(struct PARSE_STATE *p) {
    int line = p->cur.line;
    switch (p->cur.type) {
        case TOK_MINUS: {
            parse_advance(p);
            struct AST_NODE *zero = ast_new(NODE_NUMBER, line);
            return ast_binary(BIN_SUB, zero, parse_unary(p), line);
        }
        case TOK_AMP:
            parse_advance(p);
            { struct AST_NODE *n = ast_new(NODE_ADDR, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_STAR:
            parse_advance(p);
            { struct AST_NODE *n = ast_new(NODE_DEREF, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_NOT:
            parse_advance(p);
            { struct AST_NODE *n = ast_new(NODE_NOT, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_TILDE:
            parse_advance(p);
            { struct AST_NODE *n = ast_new(NODE_BNOT, line); n->data.unary.value = parse_unary(p); return n; }
        case TOK_SIZEOF:
            parse_advance(p);
            { struct AST_NODE *n = ast_new(NODE_SIZEOF, line); n->data.unary.value = parse_unary(p); return n; }
        default:
            return parse_postfix(p);
    }
}

static struct AST_NODE *parse_bin(struct PARSE_STATE *p, int min_prec) {
    struct AST_NODE *l = parse_unary(p);
    for (;;) {
        uint16_t e = PARSE_BINOP[p->cur.type];
        if ((e >> 5) < min_prec) return l;
        struct TOKEN t = p->cur;
        parse_advance(p);
        l = ast_binary((enum BIN_OP)(e & 31), l, parse_bin(p, (e >> 5) + 1), t.line);
    }
}

static struct AST_NODE *parse_expression(struct PARSE_STATE *p) {
    struct AST_NODE *l = parse_bin(p, 1);
    int cop = 0;
    switch (p->cur.type) {
        case TOK_ASSIGN:     cop = 0; break;
        case TOK_PLUS_EQ:    cop = BIN_ADD + 1; break;
        case TOK_MINUS_EQ:   cop = BIN_SUB + 1; break;
        case TOK_STAR_EQ:    cop = BIN_MUL + 1; break;
        case TOK_SLASH_EQ:   cop = BIN_DIV + 1; break;
        case TOK_PERCENT_EQ: cop = BIN_MOD + 1; break;
        default: return l;
    }
    int line = p->cur.line;
    parse_advance(p);
    struct AST_NODE *n = ast_new(NODE_ASSIGN, line);
    n->data.assign.lhs = l;
    n->data.assign.cop = cop;
    n->data.assign.rhs = parse_expression(p);
    return n;
}

static struct AST_NODE *parse_block(struct PARSE_STATE *p) {
    struct AST_NODE *b = ast_new(NODE_BLOCK, p->cur.line);
    parse_expect(p, TOK_LBRACE, "expected '{'");
    while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF)
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, parse_statement(p));
    parse_expect(p, TOK_RBRACE, "expected '}'");
    return b;
}

static struct AST_NODE *parse_statement(struct PARSE_STATE *p) {
    struct TOKEN t = p->cur;
    switch (t.type) {
        case TOK_CONST: {
            parse_advance(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected const name", p->cur.line);
            if (sym_nconst >= (int)(sizeof SYM_CONSTS / sizeof *SYM_CONSTS)) die("too many consts", p->cur.line);
            SYM_CONSTS[sym_nconst].name = p->cur.text;
            parse_advance(p);
            parse_expect(p, TOK_ASSIGN, "expected '=' in const");
            long v = 0;
            int neg = p->cur.type == TOK_MINUS;
            if (neg) parse_advance(p);
            if (p->cur.type != TOK_NUMBER) die("const must be a number", p->cur.line);
            v = lex_number(p->cur.text);
            parse_advance(p);
            SYM_CONSTS[sym_nconst].value = neg ? -v : v;
            sym_nconst++;
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return ast_new(NODE_BLOCK, t.line);
        }
        case TOK_LET: {
            parse_advance(p);
            int had_ty = 0;
            struct TYPE *ty = &TYPE_INT;
            if (p->cur.type == TOK_INT || p->cur.type == TOK_CHAR || p->cur.type == TOK_STRUCT) { ty = parse_type(p); had_ty = 1; }
            if (p->cur.type != TOK_IDENTIFIER) die("expected var name", p->cur.line);
            struct AST_NODE *n = ast_new(NODE_LET, t.line);
            n->data.let.name = p->cur.text;
            n->data.let.ty = ty;
            parse_advance(p);
            while (p->cur.type == TOK_LBRACKET) {
                parse_advance(p);
                if (p->cur.type != TOK_NUMBER) die("expected array size", p->cur.line);
                int sz = (int)lex_number(p->cur.text);
                parse_advance(p);
                parse_expect(p, TOK_RBRACKET, "expected ']'");
                n->data.let.ty = type_array(sz, n->data.let.ty);
            }
            if (p->cur.type == TOK_ASSIGN) {
                parse_advance(p);
                n->data.let.value = parse_expression(p);
                if (!had_ty && n->data.let.value->type == NODE_STR) n->data.let.ty = type_pointer(&TYPE_CHAR);
            }
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_PRINT: {
            parse_advance(p);
            struct AST_NODE *n = ast_new(NODE_PRINT, t.line);
            struct AST_NODE **args = NULL; int na = 0, acap = 0;
            do { PUSH(args, na, acap, parse_expression(p)); }
            while (p->cur.type == TOK_COMMA && (parse_advance(p), 1));
            n->data.print.args = args;
            n->data.print.ncount = na;
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_IF: {
            parse_advance(p);
            parse_expect(p, TOK_LPAREN, "expected '('");
            struct AST_NODE *n = ast_new(NODE_IF, t.line);
            n->data.if_node.cond = parse_expression(p);
            parse_expect(p, TOK_RPAREN, "expected ')'");
            n->data.if_node.then = parse_statement(p);
            if (p->cur.type == TOK_ELSE) { parse_advance(p); n->data.if_node.else_ = parse_statement(p); }
            return n;
        }
        case TOK_WHILE: {
            parse_advance(p);
            parse_expect(p, TOK_LPAREN, "expected '('");
            struct AST_NODE *n = ast_new(NODE_WHILE, t.line);
            n->data.while_node.cond = parse_expression(p);
            parse_expect(p, TOK_RPAREN, "expected ')'");
            n->data.while_node.body = parse_statement(p);
            return n;
        }
        case TOK_FOR: {
            parse_advance(p);
            if (p->cur.type == TOK_IDENTIFIER && p->pos < p->count && p->tokens[p->pos].type == TOK_IN) {
                struct TOKEN rv = p->cur;
                parse_advance(p);
                parse_advance(p);
                struct AST_NODE *lo = parse_expression(p);
                parse_expect(p, TOK_DOTDOT, "expected '..'");
                struct AST_NODE *hi = parse_expression(p);
                struct AST_NODE *rn = ast_new(NODE_FOR, t.line);
                struct AST_NODE *l1 = ast_new(NODE_LET, t.line);
                l1->data.let.name = rv.text;
                l1->data.let.ty = &TYPE_INT;
                l1->data.let.value = lo;
                rn->data.for_node.init = l1;
                struct AST_NODE *iv = ast_new(NODE_VARIABLE, t.line);
                iv->data.variable.name = rv.text;
                rn->data.for_node.cond = ast_binary(BIN_LT, iv, hi, t.line);
                struct AST_NODE *ov = ast_new(NODE_VARIABLE, t.line);
                ov->data.variable.name = rv.text;
                struct AST_NODE *one = ast_new(NODE_NUMBER, t.line);
                one->data.number.value = 1;
                struct AST_NODE *inc = ast_new(NODE_ASSIGN, t.line);
                inc->data.assign.lhs = ov;
                inc->data.assign.cop = BIN_ADD + 1;
                inc->data.assign.rhs = one;
                rn->data.for_node.inc = inc;
                rn->data.for_node.body = parse_statement(p);
                return rn;
            }
            parse_expect(p, TOK_LPAREN, "expected '('");
            struct AST_NODE *n = ast_new(NODE_FOR, t.line);
            if (p->cur.type == TOK_SEMICOLON) { parse_advance(p); n->data.for_node.init = NULL; }
            else n->data.for_node.init = parse_statement(p);
            n->data.for_node.cond = (p->cur.type == TOK_SEMICOLON) ? NULL : parse_expression(p);
            parse_expect(p, TOK_SEMICOLON, "expected ';' in for");
            n->data.for_node.inc = (p->cur.type == TOK_RPAREN) ? NULL : parse_expression(p);
            parse_expect(p, TOK_RPAREN, "expected ')'");
            n->data.for_node.body = parse_statement(p);
            return n;
        }
        case TOK_SWITCH: {
            parse_advance(p);
            parse_expect(p, TOK_LPAREN, "expected '('");
            struct AST_NODE *n = ast_new(NODE_SWITCH, t.line);
            n->data.switch_node.expr = parse_expression(p);
            parse_expect(p, TOK_RPAREN, "expected ')'");
            parse_expect(p, TOK_LBRACE, "expected '{'");
            struct AST_NODE **arms = NULL; int na = 0, acap = 0; struct AST_NODE *cur = NULL;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                if (p->cur.type == TOK_CASE || p->cur.type == TOK_DEFAULT) {
                    cur = ast_new(NODE_CASE, p->cur.line);
                    cur->data.case_arm.blk = ast_new(NODE_BLOCK, p->cur.line);
                    PUSH(arms, na, acap, cur);
                    if (p->cur.type == TOK_CASE) {
                        parse_advance(p);
                        struct AST_NODE *e = parse_expression(p);
                        if (e->type != NODE_NUMBER) die("case value must be a constant", e->line);
                        cur->data.case_arm.val = e->data.number.value;
                    } else { cur->data.case_arm.is_default = 1; parse_advance(p); }
                    parse_expect(p, TOK_COLON, "expected ':'");
                } else {
                    if (!cur) die("statement outside case label", p->cur.line);
                    struct AST_NODE *b = cur->data.case_arm.blk;
                    PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, parse_statement(p));
                }
            }
            parse_expect(p, TOK_RBRACE, "expected '}'");
            n->data.switch_node.arms = arms;
            n->data.switch_node.narms = na;
            return n;
        }
        case TOK_BREAK:
            parse_advance(p);
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return ast_new(NODE_BREAK, t.line);
        case TOK_CONTINUE:
            parse_advance(p);
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return ast_new(NODE_CONTINUE, t.line);
        case TOK_RETURN: {
            parse_advance(p);
            struct AST_NODE *n = ast_new(NODE_RETURN, t.line);
            n->data.return_node.value = parse_expression(p);
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return n;
        }
        case TOK_EXTERN: {
            parse_advance(p);
            if (p->cur.type == TOK_FUNC) {
                parse_advance(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected extern func name", p->cur.line);
                struct AST_NODE *n = ast_new(NODE_EXTERN_FUNC, t.line);
                n->data.extfn.name = p->cur.text;
                parse_advance(p);
                parse_expect(p, TOK_LPAREN, "expected '('");
                int pc = 0;
                if (p->cur.type != TOK_RPAREN)
                    do {
                        if (p->cur.type != TOK_IDENTIFIER) die("expected param name", p->cur.line);
                        pc++;
                        parse_advance(p);
                    } while (p->cur.type == TOK_COMMA && (parse_advance(p), 1));
                parse_expect(p, TOK_RPAREN, "expected ')'");
                n->data.extfn.pcount = pc;
                parse_expect(p, TOK_SEMICOLON, "expected ';'");
                return n;
            }
            if (p->cur.type == TOK_LET) {
                parse_advance(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected extern let name", p->cur.line);
                struct AST_NODE *n = ast_new(NODE_EXTERN_GLOB, t.line);
                n->data.extgl.name = p->cur.text;
                parse_advance(p);
                parse_expect(p, TOK_SEMICOLON, "expected ';'");
                return n;
            }
            die("expected 'func' or 'let' after extern", t.line);
            return NULL;
        }
        case TOK_STRUCT: {
            parse_advance(p);
            if (p->cur.type != TOK_IDENTIFIER) die("expected struct tag", p->cur.line);
            char *tag = p->cur.text;
            parse_advance(p);
            parse_expect(p, TOK_LBRACE, "expected '{'");
            int base = type_nfield, nf = 0, off = 0;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                struct TYPE *ft = parse_type(p);
                if (p->cur.type != TOK_IDENTIFIER) die("expected field name", p->cur.line);
                char *fn = p->cur.text;
                parse_advance(p);
                parse_expect(p, TOK_SEMICOLON, "expected ';' after field");
                int fsz = type_size(ft);
                int al = fsz >= 8 ? 8 : (fsz >= 4 ? 4 : (fsz >= 2 ? 2 : 1));
                off = (off + al - 1) & ~(al - 1);
                if (type_nfield >= TYPE_FIELD_MAX) die("too many struct fields", p->cur.line);
                TYPE_FIELD_POOL[type_nfield++] = (struct TYPE_FIELD){ fn, ft, off };
                off += fsz; nf++;
            }
            parse_expect(p, TOK_RBRACE, "expected '}'");
            parse_expect(p, TOK_SEMICOLON, "expected ';' after struct");
            struct TYPE *st = type_record();
            st->fields = &TYPE_FIELD_POOL[base];
            st->nfield = nf;
            st->len = (off + 7) & ~7;
            if (type_nrecord >= TYPE_RECORD_MAX) die("too many structs", t.line);
            TYPE_RECORDS[type_nrecord].name = tag; TYPE_RECORDS[type_nrecord].ty = st; type_nrecord++;
            return ast_new(NODE_BLOCK, t.line);
        }
        case TOK_ENUM: {
            parse_advance(p);
            if (p->cur.type == TOK_IDENTIFIER) parse_advance(p);
            parse_expect(p, TOK_LBRACE, "expected '{'");
            long next = 0;
            while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF) {
                if (p->cur.type != TOK_IDENTIFIER) die("expected enum name", p->cur.line);
                char *nm = p->cur.text;
                parse_advance(p);
                long val = next;
                if (p->cur.type == TOK_ASSIGN) {
                    parse_advance(p);
                    struct AST_NODE *e = parse_expression(p);
                    if (e->type != NODE_NUMBER) die("enum value must be a constant", e->line);
                    val = e->data.number.value;
                }
                if (p->cur.type == TOK_COMMA) parse_advance(p);
                if (sym_nconst >= (int)(sizeof SYM_CONSTS / sizeof *SYM_CONSTS)) die("too many consts", p->cur.line);
                SYM_CONSTS[sym_nconst].name = nm; SYM_CONSTS[sym_nconst].value = val; sym_nconst++;
                next = val + 1;
            }
            parse_expect(p, TOK_RBRACE, "expected '}'");
            if (p->cur.type == TOK_SEMICOLON) parse_advance(p);
            return ast_new(NODE_BLOCK, t.line);
        }
        case TOK_LBRACE: return parse_block(p);
        case TOK_FUNC:   die("func must be top-level", t.line);
        default: {
            struct AST_NODE *e = parse_expression(p);
            parse_expect(p, TOK_SEMICOLON, "expected ';'");
            return e;
        }
    }
}

static struct AST_NODE *parse_function(struct PARSE_STATE *p, int naked) {
    int line = p->cur.line;
    parse_advance(p);
    if (p->cur.type != TOK_IDENTIFIER) die("expected func name", p->cur.line);
    struct AST_NODE *f = ast_new(NODE_FUNCTION, line);
    f->data.function.name = p->cur.text;
    f->data.function.naked = naked;
    parse_advance(p);
    parse_expect(p, TOK_LPAREN, "expected '('");
    char **params = NULL;
    int pc = 0, pcap = 0;
    if (p->cur.type != TOK_RPAREN)
        do {
            if (p->cur.type != TOK_IDENTIFIER) die("expected param name", p->cur.line);
            PUSH(params, pc, pcap, p->cur.text);
            parse_advance(p);
        } while (p->cur.type == TOK_COMMA && (parse_advance(p), 1));
    parse_expect(p, TOK_RPAREN, "expected ')'");
    f->data.function.params = params;
    f->data.function.pcount = pc;
    f->data.function.body = parse_block(p);
    return f;
}

enum OUT_FMT { FMT_ELF, FMT_BIN, FMT_PE };
static int out_format = FMT_ELF;
static long long out_load_base = 0x400000;
static char *out_entry_name;
static int out_freestanding;
static int out_raw_mode;
static int out_boot_mode;
static int out_efi_mode;
static int out_bin_fmt;
static int out_print_label;
static int out_print_str_label;
static int out_naked;

static void parse_directive(struct PARSE_STATE *p) {
    int line = p->cur.line;
    parse_advance(p);
    if (p->cur.type != TOK_IDENTIFIER) die("directive name expected", line);
    char *d = p->cur.text;
    parse_advance(p);
    if (!strcmp(d, "base")) {
        if (p->cur.type != TOK_NUMBER) die("@base needs a number", line);
        out_load_base = lex_number(p->cur.text);
        parse_advance(p);
    } else if (!strcmp(d, "entry")) {
        if (p->cur.type != TOK_IDENTIFIER) die("@entry needs a symbol", line);
        out_entry_name = p->cur.text;
        parse_advance(p);
    } else if (!strcmp(d, "bin")) out_format = FMT_BIN;
    else if (!strcmp(d, "elf")) out_format = FMT_ELF;
    else if (!strcmp(d, "pe"))  out_format = FMT_PE;
    else if (!strcmp(d, "nort")) out_freestanding = 1;
    else if (!strcmp(d, "raw")) out_raw_mode = 1;
    else if (!strcmp(d, "boot")) out_boot_mode = 1;
    else if (!strcmp(d, "efi"))  out_efi_mode = 1;
    else die("unknown directive", line);
    parse_expect(p, TOK_SEMICOLON, "expected ';' after directive");
}

static struct AST_NODE *parse_program(struct PARSE_STATE *p) {
    struct AST_NODE *root = ast_new(NODE_BLOCK, 0);
    while (p->cur.type != TOK_EOF) {
        if (p->cur.type == TOK_AT) { parse_directive(p); continue; }
        int naked = 0;
        if (p->cur.type == TOK_NAKED) { naked = 1; parse_advance(p); }
        if (naked && p->cur.type != TOK_FUNC) die("naked must precede func", p->cur.line);
        PUSH(root->data.block.stmts, root->data.block.count, root->data.block.cap,
             p->cur.type == TOK_FUNC ? parse_function(p, naked) : parse_statement(p));
    }
    return root;
}

static uint8_t emit_buf[262144];
static int emit_len, emit_entry_off, emit_is_pe, emit_pe_impsz;
static int emit_label_pos[8192], emit_nlabel = 1;
static struct { int pos, lab, g; } EMIT_PATCHES[8192];
static uint8_t emit_patch_size[8192];
static int emit_patch_base[8192];
static int emit_npatch, emit_lit_label, emit_pcb;

enum RAW_KIND {
    RAW_MOVB, RAW_MOVW, RAW_MOVL, RAW_MOVQ, RAW_XORW, RAW_XORL, RAW_MOVSREG,
    RAW_ORB, RAW_ORL, RAW_INTN, RAW_INAL, RAW_OUTAL, RAW_CRRD, RAW_CRWR,
    RAW_ST32, RAW_CLD, RAW_RDMSR, RAW_WRMSR, RAW_REPMOVSQ, RAW_JMPRAX,
    RAW_LABEL, RAW_LJMP16, RAW_LJMP32, RAW_JC, RAW_JMP, RAW_LGDTAT, RAW_GDTDESC
};
static const char *RAW_NAMES[] = {
    "set8", "set16", "set32", "set64", "xor16", "xor32", "setseg",
    "or8", "or32", "int_n", "in_al", "out_al", "readcr", "writecr",
    "setmem32", "cld", "rdmsr", "wrmsr", "rep_movsq", "jmp_rax",
    "label", "ljmp16", "ljmp32", "jc", "jmp", "lgdt_at", "gdt_desc16"
};
static const int RAW_NARGS[] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2,
    2, 0, 0, 0, 0, 0, 1, 2, 2, 1, 1, 1, 2
};
static int raw_labels[64], raw_label_ok[64];
static struct { int pos, kind, id; } RAW_PATCHES[128];
static int raw_npatch;

static const struct { const char *name; int idx; } X64_REGS[] = {
    { "AL", 0 }, { "CL", 1 }, { "DL", 2 }, { "BL", 3 }, { "AH", 4 }, { "CH", 5 }, { "DH", 6 }, { "BH", 7 },
    { "AX", 0 }, { "CX", 1 }, { "DX", 2 }, { "BX", 3 }, { "SP", 4 }, { "BP", 5 }, { "SI", 6 }, { "DI", 7 },
    { "EAX", 0 }, { "ECX", 1 }, { "EDX", 2 }, { "EBX", 3 }, { "ESP", 4 }, { "EBP", 5 }, { "ESI", 6 }, { "EDI", 7 },
    { "RAX", 0 }, { "RCX", 1 }, { "RDX", 2 }, { "RBX", 3 }, { "RSP", 4 }, { "RBP", 5 }, { "RSI", 6 }, { "RDI", 7 },
    { "R8", 8 }, { "R9", 9 }, { "R10", 10 }, { "R11", 11 }, { "R12", 12 }, { "R13", 13 }, { "R14", 14 }, { "R15", 15 },
    { "ES", 0 }, { "CS", 1 }, { "SS", 2 }, { "DS", 3 }, { "FS", 4 }, { "GS", 5 },
    { "CR0", 0 }, { "CR2", 2 }, { "CR3", 3 }, { "CR4", 4 }, { "CR8", 8 }
};
static int x64_reg_index(const char *n) {
    for (int i = 0; i < (int)(sizeof X64_REGS / sizeof *X64_REGS); i++)
        if (!strcmp(X64_REGS[i].name, n)) return X64_REGS[i].idx;
    return -1;
}
static long x64_const_value(struct AST_NODE *a, int line) {
    if (a && a->type == NODE_VARIABLE) {
        int r = x64_reg_index(a->data.variable.name);
        if (r >= 0) return r;
    }
    if (!a || a->type != NODE_NUMBER) die("intrinsic argument must be a constant", line);
    return (long)a->data.number.value;
}
static void emit_raw_defer(int kind, int id, int pos) {
    if (!out_raw_mode) die("raw label intrinsics are only valid in @raw mode", 0);
    if (raw_npatch >= (int)(sizeof RAW_PATCHES / sizeof *RAW_PATCHES)) die("too many raw patches", 0);
    RAW_PATCHES[raw_npatch].kind = kind; RAW_PATCHES[raw_npatch].id = id; RAW_PATCHES[raw_npatch].pos = pos; raw_npatch++;
}
static void emit_raw_apply(void) {
    for (int i = 0; i < raw_npatch; i++) {
        int p = RAW_PATCHES[i].pos, id = RAW_PATCHES[i].id;
        if (id < 0 || id >= 64 || !raw_label_ok[id]) die("undefined raw label", 0);
        if (RAW_PATCHES[i].kind == 0) {
            int rel = raw_labels[id] - (p + 1);
            if (rel < -128 || rel > 127) die("raw branch out of range", 0);
            emit_buf[p] = (uint8_t)rel;
        } else if (RAW_PATCHES[i].kind == 1) {
            uint16_t v = (uint16_t)(0x7C00 + raw_labels[id]);
            memcpy(emit_buf + p, &v, 2);
        } else {
            uint32_t v = (uint32_t)(0x7C00 + raw_labels[id]);
            memcpy(emit_buf + p, &v, 4);
        }
    }
}

#define EMIT(...) do {                                   \
    uint8_t _bs[] = { __VA_ARGS__ };                     \
    if (emit_len + (int)sizeof _bs > (int)sizeof emit_buf)       \
        die("code buffer overflow", 0);                  \
    memcpy(emit_buf + emit_len, _bs, sizeof _bs);                \
    emit_len += (int)sizeof _bs;                             \
} while (0)

static void emit_imm(long long v, int n) {
    if (emit_len + n > (int)sizeof emit_buf) die("code buffer overflow", 0);
    memcpy(emit_buf + emit_len, &v, n);
    emit_len += n;
}

static void x64_rbp_disp(int reg, int off) {
    if (off >= -128 && off <= 127) EMIT(0x40 | (reg << 3) | 5, (uint8_t)off);
    else { EMIT(0x80 | (reg << 3) | 5); emit_imm(off, 4); }
}

static void x64_mov_imm(long long v) {
    if (!v) { EMIT(0x48, 0x31, 0xC0); return; }
    if (out_bin_fmt && !out_raw_mode && v >= 0 && v <= 127) { EMIT(0xB8); emit_imm(v, 4); return; }
    if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x58);
    else if (v >= 0 && v <= 0xFFFFFFFFLL) { EMIT(0xB8); emit_imm(v, 4); }
    else if (v >= -2147483648LL && v <= -1) { EMIT(0x48, 0xC7, 0xC0); emit_imm(v, 4); }
    else { EMIT(0x48, 0xB8); emit_imm(v, 8); }
}

static int emit_new_label(void) {
    if (emit_nlabel >= (int)(sizeof emit_label_pos / sizeof *emit_label_pos)) die("too many labels", 0);
    return emit_nlabel++;
}
static void emit_put_label(int lab) { emit_label_pos[lab] = emit_len; }

static void emit_patch(int g, int lab) {
    if (emit_len + 4 > (int)sizeof emit_buf || emit_npatch >= (int)(sizeof EMIT_PATCHES / sizeof *EMIT_PATCHES))
        die("too many jumps", 0);
    EMIT_PATCHES[emit_npatch] = (typeof(EMIT_PATCHES[0])){ emit_len, lab, g };
    emit_patch_size[emit_npatch] = 4;
    emit_npatch++;
    emit_len += 4;
}
static void emit_rel32(int lab) { emit_patch(0, lab); }
static void emit_jmp(int lab)  { EMIT(0xE9); emit_rel32(lab); }
static void emit_jcc(int cc, int lab) { EMIT(0x0F, cc); emit_rel32(lab); }
static void emit_call(int lab) { EMIT(0xE8); emit_rel32(lab); }

#define EMIT_PE_SECT_SIZE (0x40 + 4 + 20 + 240 + 40)

static int EMIT_IAT_PATCH[16], emit_niat;
static void emit_call_iat(int slot) {
    if (emit_niat >= (int)(sizeof EMIT_IAT_PATCH / sizeof *EMIT_IAT_PATCH)) die("too many IAT calls", 0);
    EMIT(0xFF, 0x15);
    EMIT_IAT_PATCH[emit_niat++] = emit_len * 4 | slot;
    emit_imm(0, 4);
}

struct SYM_GLOBAL { char *name; struct TYPE *ty; int off; int reg; };
static struct SYM_GLOBAL SYM_GLOBALS[256];
static int sym_nglobal, sym_gsize;
static int SYM_GLOBAL_HASH[SYM_HASH_SIZE], SYM_GLOBAL_NEXT[256];
static struct SYM_GLOBAL *sym_global_find(const char *name) {
    for (int i = SYM_GLOBAL_HASH[lex_hash(name) & (SYM_HASH_SIZE - 1)]; i >= 0; i = SYM_GLOBAL_NEXT[i])
        if (!strcmp(SYM_GLOBALS[i].name, name)) return &SYM_GLOBALS[i];
    return NULL;
}
static void sym_global_hash_build(void) {
    for (int i = 0; i < SYM_HASH_SIZE; i++) SYM_GLOBAL_HASH[i] = -1;
    for (int i = sym_nglobal - 1; i >= 0; i--) { int h = lex_hash(SYM_GLOBALS[i].name) & (SYM_HASH_SIZE - 1); SYM_GLOBAL_NEXT[i] = SYM_GLOBAL_HASH[h]; SYM_GLOBAL_HASH[h] = i; }
}

static void x64_greg_load_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x8B, (uint8_t)(0xC0 | (r & 7))); }
static void x64_greg_store_rax(int r) { EMIT((uint8_t)(0x48 | (r >= 8)), 0x89, (uint8_t)(0xC0 | (r & 7))); }
static void x64_greg_load_rcx(int r) { EMIT((uint8_t)(0x48 | ((r >= 8) << 2)), 0x89, (uint8_t)(0xC0 | ((r & 7) << 3) | 1)); }
static void x64_greg_zero(int r) { EMIT((uint8_t)(0x40 | ((r >= 8) << 2) | (r >= 8)), 0x31, (uint8_t)(0xC0 | ((r & 7) << 3) | (r & 7))); }

static void emit_apply_patches(void) {
    for (int i = 0; i < emit_npatch; i++) {
        int p = EMIT_PATCHES[i].pos, t = 0, sz = emit_patch_size[i];
        int64_t rel;
        if (EMIT_PATCHES[i].g == 0) t = emit_label_pos[EMIT_PATCHES[i].lab];
        else if (EMIT_PATCHES[i].g == 1) t = emit_label_pos[emit_lit_label] + EMIT_PATCHES[i].lab;
        else if (EMIT_PATCHES[i].g == 3) t = emit_label_pos[EMIT_PATCHES[i].lab];
        if (EMIT_PATCHES[i].g == 3) rel = t - emit_label_pos[emit_patch_base[i]];
        else if (EMIT_PATCHES[i].g < 2) rel = t - (p + sz);
        else if (emit_is_pe)
            rel = (int64_t)emit_pcb + ((emit_len + 15) & ~15) + emit_pe_impsz + EMIT_PATCHES[i].lab - (emit_pcb + p + 4);
        else {
            int64_t hdr = 64 + 56;
            int64_t dva = 0x400000 + hdr + emit_len;
            rel = dva + EMIT_PATCHES[i].lab - (0x400000 + hdr + p + 4);
        }
        if (sz == 1) emit_buf[p] = (uint8_t)(int8_t)rel;
        else *(int32_t *)(emit_buf + p) = (int32_t)rel;
    }
}

static uint8_t emit_sh_del[262144], emit_sh_new[262144];
static int emit_sh_map[262144 + 1];
static int emit_sh_flag[8192], emit_sh_kind[8192], emit_sh_patch[8192], emit_sh_nc;

static void emit_shrink_relayout(void) {
    emit_sh_nc = 0;
    for (int i = 0; i < emit_npatch; i++) {
        if (EMIT_PATCHES[i].g != 0) continue;
        int p = EMIT_PATCHES[i].pos;
        emit_sh_flag[i] = 0;
        if (emit_buf[p - 1] == 0xE9) { emit_sh_patch[emit_sh_nc] = i; emit_sh_kind[emit_sh_nc] = 0; emit_sh_nc++; }
        else if (emit_buf[p - 2] == 0x0F && (emit_buf[p - 1] & 0xF0) == 0x80) { emit_sh_patch[emit_sh_nc] = i; emit_sh_kind[emit_sh_nc] = 1; emit_sh_nc++; }
    }
    int oldlen = emit_len;
    for (int iter = 0; iter < 64; iter++) {
        memset(emit_sh_del, 0, oldlen);
        for (int k = 0; k < emit_sh_nc; k++) {
            if (!emit_sh_flag[emit_sh_patch[k]]) continue;
            int p = EMIT_PATCHES[emit_sh_patch[k]].pos;
            if (emit_sh_kind[k] == 1) emit_sh_del[p - 1] = 1;
            emit_sh_del[p + 1] = emit_sh_del[p + 2] = emit_sh_del[p + 3] = 1;
        }
        int c = 0;
        for (int x = 0; x <= oldlen; x++) { emit_sh_map[x] = c; if (x < oldlen && !emit_sh_del[x]) c++; }
        int changed = 0;
        for (int k = 0; k < emit_sh_nc; k++) {
            int i = emit_sh_patch[k]; if (emit_sh_flag[i]) continue;
            int p = EMIT_PATCHES[i].pos;
            int rel = emit_sh_map[emit_label_pos[EMIT_PATCHES[i].lab]] - (emit_sh_map[p] + 1);
            if (rel >= -128 && rel <= 127) { emit_sh_flag[i] = 1; changed = 1; }
        }
        if (!changed) break;
    }
    for (int k = 0; k < emit_sh_nc; k++) {
        int i = emit_sh_patch[k]; if (!emit_sh_flag[i]) continue;
        int p = EMIT_PATCHES[i].pos;
        if (emit_sh_kind[k] == 0) emit_buf[p - 1] = 0xEB;
        else emit_buf[p - 2] = (uint8_t)((emit_buf[p - 1] & 0x0F) | 0x70);
    }
    int w = 0;
    for (int x = 0; x < oldlen; x++) if (!emit_sh_del[x]) emit_sh_new[w++] = emit_buf[x];
    memcpy(emit_buf, emit_sh_new, w);
    for (int l = 0; l < emit_nlabel; l++) emit_label_pos[l] = emit_sh_map[emit_label_pos[l]];
    emit_entry_off = emit_sh_map[emit_entry_off];
    for (int i = 0; i < emit_npatch; i++) {
        EMIT_PATCHES[i].pos = emit_sh_map[EMIT_PATCHES[i].pos];
        if (EMIT_PATCHES[i].g == 0 && emit_sh_flag[i]) emit_patch_size[i] = 1;
    }
    for (int i = 0; i < emit_niat; i++) EMIT_IAT_PATCH[i] = (emit_sh_map[EMIT_IAT_PATCH[i] >> 2] << 2) | (EMIT_IAT_PATCH[i] & 3);
    emit_len = w;
}

struct SYM_LOCAL { char *name; struct TYPE *ty; int off; };
static struct SYM_LOCAL SYM_LOCALS[256];
static int sym_nlocal, sym_frame_off, sym_frame_min;
static struct SYM_LOCAL *sym_local_add(const char *name, struct TYPE *ty) {
    if (sym_nlocal >= (int)(sizeof SYM_LOCALS / sizeof *SYM_LOCALS)) die("too many locals", 0);
    sym_frame_off -= type_size(ty);
    if (sym_frame_off < sym_frame_min) sym_frame_min = sym_frame_off;
    SYM_LOCALS[sym_nlocal] = (struct SYM_LOCAL){ (char *)name, ty, sym_frame_off };
    return &SYM_LOCALS[sym_nlocal++];
}
static struct SYM_LOCAL *sym_local_find(const char *name) {
    for (int i = sym_nlocal - 1; i >= 0; i--)
        if (!strcmp(SYM_LOCALS[i].name, name)) return &SYM_LOCALS[i];
    return NULL;
}

static struct { char *name; int lab, params; } SYM_FUNCS[256];
static int sym_nfunc;
static int sym_break_labels[64], sym_cont_labels[64], sym_nloop;
static int SYM_FUNC_HASH[SYM_HASH_SIZE], SYM_FUNC_NEXT[256];
static int sym_func_find(const char *name) {
    for (int i = SYM_FUNC_HASH[lex_hash(name) & (SYM_HASH_SIZE - 1)]; i >= 0; i = SYM_FUNC_NEXT[i])
        if (!strcmp(SYM_FUNCS[i].name, name)) return i;
    return -1;
}
static void sym_func_hash_build(void) {
    for (int i = 0; i < SYM_HASH_SIZE; i++) SYM_FUNC_HASH[i] = -1;
    for (int i = sym_nfunc - 1; i >= 0; i--) { int h = lex_hash(SYM_FUNCS[i].name) & (SYM_HASH_SIZE - 1); SYM_FUNC_NEXT[i] = SYM_FUNC_HASH[h]; SYM_FUNC_HASH[h] = i; }
}

static int x64_setcc_of(enum BIN_OP op) {
    return op < BIN_LT ? 0x90 | op : 0x9C | (-(op - BIN_LT) & 3);
}

static void x64_emit_binop(enum BIN_OP op) {
    switch (op) {
        case BIN_ADD: EMIT(0x48, 0x01, 0xC8); break;
        case BIN_SUB: EMIT(0x48, 0x29, 0xC8); break;
        case BIN_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC1); break;
        case BIN_DIV: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9); break;
        case BIN_MOD: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9, 0x48, 0x89, 0xD0); break;
        case BIN_BOR:  EMIT(0x48, 0x09, 0xC8); break;
        case BIN_BAND: EMIT(0x48, 0x21, 0xC8); break;
        case BIN_BXOR: EMIT(0x48, 0x31, 0xC8); break;
        case BIN_SHL:  EMIT(0x48, 0xD3, 0xE0); break;
        case BIN_SHR:  EMIT(0x48, 0xD3, 0xF8); break;
        default:
            EMIT(0x48, 0x39, 0xC8);
            EMIT(0x0F, x64_setcc_of(op), 0xC0);
            EMIT(0x0F, 0xB6, 0xC0);
            break;
    }
}

static int x64_try_leaf_rcx(struct AST_NODE *n) {
    if (n->type != NODE_VARIABLE) return 0;
    struct SYM_LOCAL *l = sym_local_find(n->data.variable.name);
    if (l) {
        if (l->ty->kind != 0) return 0;
        if (type_is_char(l->ty)) { EMIT(0x0F, 0xB6); x64_rbp_disp(1, l->off); }
        else { EMIT(0x48, 0x8B); x64_rbp_disp(1, l->off); }
        return 1;
    }
    struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
    if (!g || g->ty->kind != 0) return 0;
    if (g->reg) { x64_greg_load_rcx(g->reg); return 1; }
    if (type_is_char(g->ty)) { EMIT(0x0F, 0xB6, 0x0D); emit_patch(2, g->off); }
    else { EMIT(0x48, 0x8B, 0x0D); emit_patch(2, g->off); }
    return 1;
}

static void x64_emit_cmp_imm(long long v) {
    if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xF8, (uint8_t)v);
    else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x3D); emit_imm(v, 4); }
    else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x39, 0xC8); }
}

static void x64_emit_print_pe(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x50);
    EMIT(0x45,0x31,0xDB);
    EMIT(0x48,0x85,0xC0);
    int pos = emit_new_label();
    emit_jcc(0x89, pos);
    EMIT(0x48,0xF7,0xD8);
    EMIT(0x41,0xBB,1,0,0,0);
    emit_put_label(pos);
    EMIT(0x6A,0x0A,0x59);
    EMIT(0x48,0x8D,0x75,0xFF);
    int loop = emit_new_label();
    emit_put_label(loop);
    EMIT(0x48,0x31,0xD2);
    EMIT(0x48,0xF7,0xF1);
    EMIT(0x80,0xC2,0x30);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0x88,0x16);
    EMIT(0x48,0x85,0xC0);
    emit_jcc(0x85, loop);
    EMIT(0x45,0x85,0xDB);
    int wr = emit_new_label();
    emit_jcc(0x84, wr);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0xC6,0x06,0x2D);
    emit_put_label(wr);
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

static void x64_emit_print_elf(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x20);
    EMIT(0x45,0x31,0xDB);
    EMIT(0x48,0x85,0xC0);
    int pos = emit_new_label();
    emit_jcc(0x89, pos);
    EMIT(0x48,0xF7,0xD8);
    EMIT(0x41,0xBB,1,0,0,0);
    emit_put_label(pos);
    EMIT(0x6A,0x0A,0x59);
    EMIT(0x48,0x8D,0x75,0xFF);
    int loop = emit_new_label();
    emit_put_label(loop);
    EMIT(0x48,0x31,0xD2);
    EMIT(0x48,0xF7,0xF1);
    EMIT(0x80,0xC2,0x30);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0x88,0x16);
    EMIT(0x48,0x85,0xC0);
    emit_jcc(0x85, loop);
    EMIT(0x45,0x85,0xDB);
    int wr = emit_new_label();
    emit_jcc(0x84, wr);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0xC6,0x06,0x2D);
    emit_put_label(wr);
    EMIT(0x48,0x8D,0x55,0xFF);
    EMIT(0x48,0x29,0xF2);
    EMIT(0x6A,0x01,0x58);
    EMIT(0x89,0xC7);
    EMIT(0x0F,0x05);
    EMIT(0xC9,0xC3);
}

static void x64_emit_print_bare(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x20);
    EMIT(0x45,0x31,0xDB);
    EMIT(0x48,0x85,0xC0);
    int pos = emit_new_label();
    emit_jcc(0x89, pos);
    EMIT(0x48,0xF7,0xD8);
    EMIT(0x41,0xBB,1,0,0,0);
    emit_put_label(pos);
    EMIT(0x6A,0x0A,0x59);
    EMIT(0x48,0x8D,0x75,0xFF);
    int loop = emit_new_label();
    emit_put_label(loop);
    EMIT(0x48,0x31,0xD2);
    EMIT(0x48,0xF7,0xF1);
    EMIT(0x80,0xC2,0x30);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0x88,0x16);
    EMIT(0x48,0x85,0xC0);
    emit_jcc(0x85, loop);
    EMIT(0x45,0x85,0xDB);
    int wr = emit_new_label();
    emit_jcc(0x84, wr);
    EMIT(0x48,0xFF,0xCE);
    EMIT(0xC6,0x06,0x2D);
    emit_put_label(wr);
    EMIT(0x66,0xBA,0xF8,0x03);
    int oloop = emit_new_label();
    emit_put_label(oloop);
    EMIT(0x48,0x39,0xEE);
    int onl = emit_new_label();
    emit_jcc(0x83, onl);
    EMIT(0x8A,0x06);
    EMIT(0xEE);
    EMIT(0x48,0xFF,0xC6);
    emit_jmp(oloop);
    emit_put_label(onl);
    EMIT(0xB0,0x0A);
    EMIT(0xEE);
    EMIT(0xC9,0xC3);
}

static void x64_emit_print_str_elf(void) {
    EMIT(0x48,0x89,0xC6);
    EMIT(0x48,0x89,0xF2);
    int scan = emit_new_label();
    emit_put_label(scan);
    EMIT(0x0F,0xB6,0x02);
    EMIT(0x84,0xC0);
    int done = emit_new_label();
    emit_jcc(0x84, done);
    EMIT(0x48,0xFF,0xC2);
    emit_jmp(scan);
    emit_put_label(done);
    EMIT(0x48,0x29,0xF2);
    EMIT(0x6A,0x01,0x58);
    EMIT(0x6A,0x01,0x5F);
    EMIT(0x0F,0x05);
    EMIT(0xC3);
}

static void x64_emit_print_str_pe(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x50);
    EMIT(0x48,0x89,0xC6);
    EMIT(0x48,0x89,0xF2);
    int scan = emit_new_label();
    emit_put_label(scan);
    EMIT(0x0F,0xB6,0x02);
    EMIT(0x84,0xC0);
    int done = emit_new_label();
    emit_jcc(0x84, done);
    EMIT(0x48,0xFF,0xC2);
    emit_jmp(scan);
    emit_put_label(done);
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

static void x64_emit_print_str_bare(void) {
    EMIT(0x55);
    EMIT(0x48,0x89,0xE5);
    EMIT(0x48,0x83,0xEC,0x20);
    EMIT(0x48,0x89,0xC6);
    EMIT(0x66,0xBA,0xF8,0x03);
    int oloop = emit_new_label();
    emit_put_label(oloop);
    EMIT(0x0F,0xB6,0x06);
    EMIT(0x84,0xC0);
    int done = emit_new_label();
    emit_jcc(0x84, done);
    EMIT(0xEE);
    EMIT(0x48,0xFF,0xC6);
    emit_jmp(oloop);
    emit_put_label(done);
    EMIT(0xB0,0x0A);
    EMIT(0xEE);
    EMIT(0xC9,0xC3);
}

static void x64_gen_expr(struct AST_NODE*);
static void x64_gen_stmt(struct AST_NODE*);

static void x64_mov_imm(long long v);

static int type_size_of_expr(struct AST_NODE *n) {
    if (n->type == NODE_VARIABLE) {
        struct SYM_LOCAL *l = sym_local_find(n->data.variable.name);
        if (l) return type_size(l->ty);
        struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
        if (g) return type_size(g->ty);
        return 8;
    }
    if (n->type == NODE_STR) return 8;
    return 8;
}

static struct TYPE *type_of_expr(struct AST_NODE *n);
static struct TYPE *type_struct_of(struct AST_NODE *b, int arrow) {
    struct TYPE *bt = type_of_expr(b);
    if (arrow) { if (bt->kind != 1) die("-> applied to non-pointer", b->line); bt = bt->base; }
    if (!bt || bt->kind != 3) die("member access on non-struct", b->line);
    return bt;
}

static struct TYPE *type_of_expr(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            struct SYM_LOCAL *l = sym_local_find(n->data.variable.name);
            if (l) return l->ty;
            struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
            return g ? g->ty : &TYPE_INT;
        }
        case NODE_STR:    return type_pointer(&TYPE_CHAR);
        case NODE_DEREF:  return type_of_expr(n->data.unary.value)->kind ? type_of_expr(n->data.unary.value)->base : &TYPE_INT;
        case NODE_INDEX:  return type_of_expr(n->data.index.base)->kind ? type_of_expr(n->data.index.base)->base : &TYPE_INT;
        case NODE_ADDR:   return type_pointer(type_of_expr(n->data.unary.value));
        case NODE_MEMBER: {
            struct TYPE *st = type_struct_of(n->data.member.base, n->data.member.arrow);
            struct TYPE_FIELD *f = type_find_field(st, n->data.member.field);
            if (!f) die("no such field", n->line);
            return f->ty;
        }
        default:          return &TYPE_INT;
    }
}

static int type_is_str(struct TYPE *t) {
    return (t->kind == 1 || t->kind == 2) && type_is_char(t->base);
}
static int type_is_str_arg(struct AST_NODE *e) { return type_is_str(type_of_expr(e)); }

static void x64_gen_addr(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            struct SYM_LOCAL *l = sym_local_find(n->data.variable.name);
            if (l) { EMIT(0x48, 0x8D); x64_rbp_disp(0, l->off); break; }
            struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
            if (!g) die("undefined variable", n->line);
            if (g->reg) die("cannot take address of a register-resident global", n->line);
            EMIT(0x48, 0x8D, 0x05);
            emit_patch(2, g->off);
            break;
        }
        case NODE_DEREF:
            x64_gen_expr(n->data.unary.value);
            break;
        case NODE_INDEX: {
            struct TYPE *bt = type_of_expr(n->data.index.base);
            if (bt->kind == 1) x64_gen_expr(n->data.index.base);
            else x64_gen_addr(n->data.index.base);
            EMIT(0x50);
            x64_gen_expr(n->data.index.index);
            int es = type_size(type_of_expr(n));
            if (es == 8) EMIT(0x48, 0xC1, 0xE0, 0x03);
            else if (es != 1) { EMIT(0x48, 0x69, 0xC0); emit_imm(es, 4); }
            EMIT(0x5B, 0x48, 0x01, 0xD8);
            break;
        }
        case NODE_MEMBER: {
            struct AST_NODE *b = n->data.member.base;
            int arrow = n->data.member.arrow;
            struct TYPE *st = type_struct_of(b, arrow);
            struct TYPE_FIELD *f = type_find_field(st, n->data.member.field);
            if (!f) die("no such field", n->line);
            if (arrow) x64_gen_expr(b); else x64_gen_addr(b);
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

static void x64_gen_expr(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_NUMBER:
            x64_mov_imm(n->data.number.value);
            break;
        case NODE_VARIABLE: {
            struct SYM_LOCAL *l = sym_local_find(n->data.variable.name);
            if (l) {
                if (l->ty->kind == 2) { EMIT(0x48, 0x8D); x64_rbp_disp(0, l->off); }
                else if (type_is_char(l->ty)) { EMIT(0x0F, 0xB6); x64_rbp_disp(0, l->off); }
                else { EMIT(0x48, 0x8B); x64_rbp_disp(0, l->off); }
                break;
            }
            struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
            if (!g) die("undefined variable", n->line);
            if (g->reg) { x64_greg_load_rax(g->reg); break; }
            if (g->ty->kind == 2) { EMIT(0x48, 0x8D, 0x05); emit_patch(2, g->off); }
            else if (type_is_char(g->ty)) { EMIT(0x0F, 0xB6, 0x05); emit_patch(2, g->off); }
            else { EMIT(0x48, 0x8B, 0x05); emit_patch(2, g->off); }
            break;
        }
        case NODE_STR:
            EMIT(0x48, 0x8D, 0x05);
            emit_patch(1, n->data.str.off);
            break;
        case NODE_ADDR:
            x64_gen_addr(n->data.unary.value);
            break;
        case NODE_DEREF:
            x64_gen_expr(n->data.unary.value);
            if (type_is_char(type_of_expr(n))) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        case NODE_INDEX:
            x64_gen_addr(n);
            if (type_is_char(type_of_expr(n))) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        case NODE_MEMBER: {
            struct TYPE *ft = type_of_expr(n);
            x64_gen_addr(n);
            if (ft->kind == 2 || ft->kind == 3) { }
            else if (type_is_char(ft)) EMIT(0x0F, 0xB6, 0x00);
            else EMIT(0x48, 0x8B, 0x00);
            break;
        }
        case NODE_ASSIGN: {
            int cop = n->data.assign.cop ? n->data.assign.cop - 1 : -1;
            struct AST_NODE *lhs = n->data.assign.lhs;
            struct SYM_LOCAL *l = NULL; struct SYM_GLOBAL *g = NULL; struct TYPE *ty = NULL;
            if (lhs->type == NODE_VARIABLE) {
                l = sym_local_find(lhs->data.variable.name);
                if (l) ty = l->ty;
                else { g = sym_global_find(lhs->data.variable.name); if (g) ty = g->ty; }
            }
            if (g && g->reg) {
                int r = g->reg;
                x64_gen_expr(n->data.assign.rhs);
                if (cop < 0) { x64_greg_store_rax(r); break; }
                int sync = 1;
                switch (cop) {
                    case BIN_ADD: EMIT((uint8_t)(0x48 | (r >= 8)), 0x01, (uint8_t)(0xC0 | (r & 7))); break;
                    case BIN_SUB: EMIT((uint8_t)(0x48 | (r >= 8)), 0x29, (uint8_t)(0xC0 | (r & 7))); break;
                    case BIN_MUL: EMIT(0x4C, 0x0F, 0xAF, (uint8_t)(0xC0 | ((r & 7) << 3))); break;
                    default: {
                        x64_greg_load_rcx(r);
                        x64_greg_store_rax(r);
                        EMIT(0x48, 0x89, 0xC8);
                        EMIT(0x48, 0x99);
                        EMIT((uint8_t)(0x48 | (r >= 8)), 0xF7, (uint8_t)(0xC0 | 0x38 | (r & 7)));
                        if (cop == BIN_MOD) EMIT(0x48, 0x89, 0xD0);
                        x64_greg_store_rax(r);
                        sync = 0;
                        break;
                    }
                }
                if (sync) x64_greg_load_rax(r);
                break;
            }
            if (ty && ty->kind == 0 && (cop < 0 || (!type_is_char(ty) && (cop == BIN_ADD || cop == BIN_SUB)))) {
                x64_gen_expr(n->data.assign.rhs);
                if (cop < 0) {
                    if (l) { EMIT(type_is_char(ty) ? 0x88 : 0x48, 0x89); x64_rbp_disp(0, l->off); }
                    else { EMIT(type_is_char(ty) ? 0x88 : 0x48, 0x89, 0x05); emit_patch(2, g->off); }
                } else {
                    int opc = cop == BIN_ADD ? 0x01 : 0x29;
                    if (l) { EMIT(0x48, opc); x64_rbp_disp(0, l->off); }
                    else { EMIT(0x48, opc, 0x05); emit_patch(2, g->off); }
                }
                break;
            }
            x64_gen_addr(lhs);
            EMIT(0x50);
            x64_gen_expr(n->data.assign.rhs);
            EMIT(0x5B);
            if (cop >= 0) {
                EMIT(0x48, 0x8B, 0x0B);
                EMIT(0x48, 0x91);
                switch (cop) {
                    case BIN_ADD: EMIT(0x48, 0x01, 0xC8); break;
                    case BIN_SUB: EMIT(0x48, 0x29, 0xC8); break;
                    case BIN_MUL: EMIT(0x48, 0x0F, 0xAF, 0xC1); break;
                    case BIN_DIV: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9); break;
                    case BIN_MOD: EMIT(0x48, 0x99, 0x48, 0xF7, 0xF9, 0x48, 0x89, 0xD0); break;
                }
            }
            if (type_is_char(type_of_expr(lhs))) EMIT(0x88, 0x03);
            else EMIT(0x48, 0x89, 0x03);
            break;
        }
        case NODE_SIZEOF:
            x64_mov_imm(type_size_of_expr(n->data.unary.value));
            break;
        case NODE_NOT:
            x64_gen_expr(n->data.unary.value);
            EMIT(0x48, 0x85, 0xC0);
            EMIT(0x0F, 0x94, 0xC0);
            EMIT(0x0F, 0xB6, 0xC0);
            break;
        case NODE_BNOT:
            x64_gen_expr(n->data.unary.value);
            EMIT(0x48, 0xF7, 0xD0);
            break;
        case NODE_BINARY: {
            enum BIN_OP op = n->data.binary.op;
            struct AST_NODE *r = n->data.binary.right;
            if (op == BIN_AND || op == BIN_OR) {
                int lab_sc = emit_new_label(), lab_end = emit_new_label();
                int cc = op == BIN_AND ? 0x84 : 0x85;
                int v_norm = op == BIN_AND ? 1 : 0;
                x64_gen_expr(n->data.binary.left);
                EMIT(0x48, 0x85, 0xC0);
                emit_jcc(cc, lab_sc);
                x64_gen_expr(r);
                EMIT(0x48, 0x85, 0xC0);
                emit_jcc(cc, lab_sc);
                x64_mov_imm(v_norm);
                emit_jmp(lab_end);
                emit_put_label(lab_sc);
                x64_mov_imm(1 - v_norm);
                emit_put_label(lab_end);
                break;
            }
            if (r->type == NODE_NUMBER) {
                long long v = r->data.number.value;
                x64_gen_expr(n->data.binary.left);
                switch (op) {
                    case BIN_ADD:
                        if (v) {
                            if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xC0, (uint8_t)v);
                            else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x05); emit_imm(v, 4); }
                            else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x01, 0xC8); }
                        }
                        break;
                    case BIN_SUB:
                        if (v) {
                            if (v >= -128 && v <= 127) EMIT(0x48, 0x83, 0xE8, (uint8_t)v);
                            else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x2D); emit_imm(v, 4); }
                            else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x29, 0xC8); }
                        }
                        break;
                    case BIN_MUL:
                        if (v == 1) break;
                        if (!v) { EMIT(0x48, 0x31, 0xC0); break; }
                        if (v >= -128 && v <= 127) EMIT(0x48, 0x6B, 0xC0, (uint8_t)v);
                        else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x69, 0xC0); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x0F, 0xAF, 0xC1); }
                        break;
                    case BIN_DIV:
                    case BIN_MOD:
                        EMIT(0x48, 0x99);
                        if (out_bin_fmt && !out_raw_mode && v >= 0 && v <= 127) { EMIT(0xB9); emit_imm(v, 4); }
                        else if (v >= -128 && v <= 127) EMIT(0x6A, (uint8_t)v, 0x59);
                        else if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0xC7, 0xC1); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); }
                        EMIT(0x48, 0xF7, 0xF9);
                        if (op == BIN_MOD) EMIT(0x48, 0x89, 0xD0);
                        break;
                    case BIN_BOR:
                        if (!v) break;
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x0D); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x09, 0xC8); }
                        break;
                    case BIN_BAND:
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x25); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x21, 0xC8); }
                        break;
                    case BIN_BXOR:
                        if (!v) break;
                        if (v >= -2147483648LL && v <= 2147483647LL) { EMIT(0x48, 0x35); emit_imm(v, 4); }
                        else { EMIT(0x48, 0xB9); emit_imm(v, 8); EMIT(0x48, 0x31, 0xC8); }
                        break;
                    case BIN_SHL:
                        EMIT(0x48, 0xC1, 0xE0, (uint8_t)(v & 63)); break;
                    case BIN_SHR:
                        EMIT(0x48, 0xC1, 0xF8, (uint8_t)(v & 63)); break;
                    default:
                        x64_emit_cmp_imm(v);
                        EMIT(0x0F, x64_setcc_of(op), 0xC0);
                        EMIT(0x0F, 0xB6, 0xC0);
                        break;
                }
                break;
            }
            x64_gen_expr(n->data.binary.left);
            if (x64_try_leaf_rcx(r)) { x64_emit_binop(op); break; }
            EMIT(0x50);
            x64_gen_expr(r);
            EMIT(0x59);
            EMIT(0x48, 0x91);
            x64_emit_binop(op);
            break;
        }
        case NODE_CALL: {
            const char *nm = n->data.call.name;
            int ac = n->data.call.acount;
            if (!strcmp(nm, "asm")) {
                for (int i = 0; i < ac; i++) {
                    struct AST_NODE *a = n->data.call.args[i];
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
                if (!strcmp(nm, "setcr3") && !out_bin_fmt) die("intrinsic is only available in bin output", n->line);
                x64_gen_expr(n->data.call.args[0]);
                if (!strcmp(nm, "lgdt")) EMIT(0x0F, 0x01, 0x10);
                else if (!strcmp(nm, "lidt")) EMIT(0x0F, 0x01, 0x18);
                else EMIT(0x0F, 0x22, 0xD8);
                break;
            }
            if (!strcmp(nm, "addr") && sym_func_find(nm) < 0) {
                if (ac != 1 || n->data.call.args[0]->type != NODE_VARIABLE)
                    die("addr(funcname)", n->line);
                int f = sym_func_find(n->data.call.args[0]->data.variable.name);
                if (f < 0) die("addr: unknown function", n->line);
                EMIT(0x48, 0x8D, 0x05);
                emit_patch(0, SYM_FUNCS[f].lab);
                break;
            }
            if (!strcmp(nm, "ld32") && sym_func_find(nm) < 0) {
                if (ac != 1) die("ld32(addr)", n->line);
                x64_gen_expr(n->data.call.args[0]);
                EMIT(0x8B, 0x00);
                break;
            }
            if (!strcmp(nm, "st32") && sym_func_find(nm) < 0) {
                if (ac != 2) die("st32(addr, val)", n->line);
                x64_gen_expr(n->data.call.args[1]);
                EMIT(0x50);
                x64_gen_expr(n->data.call.args[0]);
                EMIT(0x59);
                EMIT(0x89, 0x08);
                break;
            }
            if (!strcmp(nm, "inb") || !strcmp(nm, "inl")) {
                if (ac != 1) die("inb(port)", n->line);
                struct AST_NODE *a = n->data.call.args[0];
                if (a->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(a->data.number.value, 2); }
                else { x64_gen_expr(a); EMIT(0x66, 0x89, 0xC2); }
                if (nm[2] == 'l') EMIT(0xED);
                else { EMIT(0xEC); EMIT(0x0F, 0xB6, 0xC0); }
                break;
            }
            if (!strcmp(nm, "outb") || !strcmp(nm, "outl")) {
                if (ac != 2) die("outb(port, value)", n->line);
                struct AST_NODE *pa = n->data.call.args[0];
                x64_gen_expr(n->data.call.args[1]);
                EMIT(0x50);
                if (pa->type == NODE_NUMBER) { EMIT(0x66, 0xBA); emit_imm(pa->data.number.value, 2); }
                else { x64_gen_expr(pa); EMIT(0x66, 0x89, 0xC2); }
                EMIT(0x58);
                EMIT(nm[3] == 'l' ? 0xEF : 0xEE);
                break;
            }
            {
                int ri = -1;
                for (int k = 0; k < (int)(sizeof RAW_NAMES / sizeof *RAW_NAMES); k++)
                    if (!strcmp(nm, RAW_NAMES[k])) { ri = k; break; }
                if (ri < 0) goto not_intrinsic;
                if (ac != RAW_NARGS[ri]) die("intrinsic: wrong argument count", n->line);
                if (((0x71FFu >> ri) & 1) && !out_bin_fmt && !out_efi_mode) die("intrinsic is only available in bin output", n->line);
                long a0 = ac > 0 ? x64_const_value(n->data.call.args[0], n->line) : 0;
                long a1 = ac > 1 ? x64_const_value(n->data.call.args[1], n->line) : 0;
                switch (ri) {
                case RAW_MOVB:  EMIT(0xB0 + (a0 & 7), (uint8_t)a1); break;
                case RAW_MOVW:  EMIT(0xB8 + (a0 & 7)); emit_imm(a1, 2); break;
                case RAW_MOVL:  EMIT(0xB8 + (a0 & 7)); emit_imm(a1, 4); break;
                case RAW_MOVQ:  EMIT(0x48, 0xC7, 0xC0 + (a0 & 7)); emit_imm(a1, 4); break;
                case RAW_XORW:
                case RAW_XORL:  EMIT(0x31, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RAW_MOVSREG: EMIT(0x8E, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RAW_ORB:   EMIT(0x0C + (a0 & 7), (uint8_t)a1); break;
                case RAW_ORL:   EMIT(0x0D + (a0 & 7)); emit_imm(a1, 4); break;
                case RAW_INTN:  EMIT(0xCD, (uint8_t)a0); break;
                case RAW_INAL:  EMIT(0xE4, (uint8_t)a0); break;
                case RAW_OUTAL: EMIT(0xE6, (uint8_t)a0); break;
                case RAW_CRRD:  EMIT(0x0F, 0x20, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RAW_CRWR:  EMIT(0x0F, 0x22, 0xC0 | ((a0 & 7) << 3) | (a1 & 7)); break;
                case RAW_ST32:  EMIT(0xC7, 0x05); emit_imm(a0, 4); emit_imm(a1, 4); break;
                case RAW_CLD:   EMIT(0xFC); break;
                case RAW_RDMSR: EMIT(0x0F, 0x32); break;
                case RAW_WRMSR: EMIT(0x0F, 0x30); break;
                case RAW_REPMOVSQ: EMIT(0xF3, 0x48, 0xA5); break;
                case RAW_JMPRAX: EMIT(0xFF, 0xE0); break;
                case RAW_LABEL:
                    if (!out_raw_mode) die("label() is only valid in @raw mode", n->line);
                    if (a0 < 0 || a0 >= 64) die("raw label id out of range", n->line);
                    raw_labels[a0] = emit_len; raw_label_ok[a0] = 1;
                    break;
                case RAW_JC:   EMIT(0x72, 0); emit_raw_defer(0, (int)a0, emit_len - 1); break;
                case RAW_JMP:  EMIT(0xEB, 0); emit_raw_defer(0, (int)a0, emit_len - 1); break;
                case RAW_LJMP16: EMIT(0xEA); emit_raw_defer(1, (int)a1, emit_len); emit_imm(0, 2); emit_imm(a0, 2); break;
                case RAW_LJMP32: EMIT(0xEA); emit_raw_defer(2, (int)a1, emit_len); emit_imm(0, 4); emit_imm(a0, 2); break;
                case RAW_LGDTAT: EMIT(0x0F, 0x01, 0x16); emit_raw_defer(1, (int)a0, emit_len); emit_imm(0, 2); break;
                case RAW_GDTDESC: emit_imm(a1 - 1, 2); emit_raw_defer(2, (int)a0, emit_len); emit_imm(0, 4); break;
                }
                break;
            }
        not_intrinsic:
            if (!strcmp(nm, "syscall")) {
                if (n->data.call.acount < 1 || n->data.call.args[0]->type != NODE_NUMBER)
                    die("syscall(nr, a, b, c)", n->line);
                long nr = n->data.call.args[0]->data.number.value;
                if (emit_is_pe) {
                    if (nr != 60) die("syscall: only exit(60) on PE", n->line);
                    x64_gen_expr(n->data.call.args[1]);
                    EMIT(0x48, 0x89, 0xC1);
                    emit_call_iat(2);
                    break;
                }
                if (n->data.call.acount != 4) die("syscall(nr, a, b, c)", n->line);
                for (int i = 3; i >= 1; i--) { x64_gen_expr(n->data.call.args[i]); EMIT(0x50); }
                EMIT(0x5F, 0x5E, 0x5A);
                x64_mov_imm(nr);
                EMIT(0x0F, 0x05);
                break;
            }
            int f = sym_func_find(n->data.call.name);
            if (f < 0) { fprintf(stderr, "error (line %d): unknown func %s\n", n->line, n->data.call.name); exit(1); }
            if (ac != SYM_FUNCS[f].params) {
                fprintf(stderr, "error (line %d): %s expects %d args, got %d\n",
                        n->line, n->data.call.name, SYM_FUNCS[f].params, ac);
                exit(1);
            }
            if (ac == 0) {
                emit_call(SYM_FUNCS[f].lab);
            } else if (ac == 1) {
                x64_gen_expr(n->data.call.args[0]);
                EMIT(0x48, 0x89, 0xC7);
                emit_call(SYM_FUNCS[f].lab);
            } else {
                int pad = ((ac - 1) & 1) ? 8 : 0;
                if (pad) EMIT(0x48, 0x83, 0xEC, 0x08);
                for (int i = ac - 1; i >= 1; i--) { x64_gen_expr(n->data.call.args[i]); EMIT(0x50); }
                x64_gen_expr(n->data.call.args[0]);
                EMIT(0x48, 0x89, 0xC7);
                emit_call(SYM_FUNCS[f].lab);
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

static int x64_gen_cond(struct AST_NODE *c) {
    if (c->type == NODE_BINARY && c->data.binary.op >= BIN_EQ && c->data.binary.op <= BIN_GE) {
        struct AST_NODE *r = c->data.binary.right;
        x64_gen_expr(c->data.binary.left);
        if (r->type == NODE_NUMBER) x64_emit_cmp_imm(r->data.number.value);
        else if (x64_try_leaf_rcx(r)) EMIT(0x48, 0x39, 0xC8);
        else { EMIT(0x50); x64_gen_expr(r); EMIT(0x59); EMIT(0x48, 0x39, 0xC1); }
        return ((x64_setcc_of(c->data.binary.op) & 15) | 0x80) ^ 1;
    }
    x64_gen_expr(c);
    EMIT(0x48, 0x85, 0xC0);
    return 0x84;
}

static void x64_gen_stmt(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_LET: {
            if (n->data.let.value) x64_gen_expr(n->data.let.value);
            struct SYM_LOCAL *l = sym_local_add(n->data.let.name, n->data.let.ty);
            if (n->data.let.ty->kind == 2) {
                EMIT(0x48, 0x8D); x64_rbp_disp(7, l->off);
                if (n->data.let.value) EMIT(0x48, 0x89, 0x07);
                else {
                    struct TYPE *e = n->data.let.ty->base;
                    EMIT(0x48, 0x31, 0xC0);
                    EMIT(0xB9);
                    int esz = type_size(e);
                    int cnt = (e->kind == 3 && esz > 0) ? type_size(n->data.let.ty) / esz : (type_is_char(e) ? type_size(n->data.let.ty) : type_size(n->data.let.ty) / 8);
                    emit_imm(cnt, 4);
                    if (type_is_char(e)) EMIT(0xF3, 0xAA); else EMIT(0xF3, 0x48, 0xAB);
                }
            } else if (n->data.let.ty->kind == 3) {
                if (n->data.let.value) die("cannot initialize struct in place", n->line);
            } else {
                if (!n->data.let.value) die("missing initializer", n->line);
                if (type_is_char(n->data.let.ty)) { EMIT(0x88); x64_rbp_disp(0, l->off); }
                else { EMIT(0x48, 0x89); x64_rbp_disp(0, l->off); }
            }
            break;
        }
        case NODE_PRINT:
            if (out_freestanding && !out_boot_mode) die("print is unavailable in freestanding mode", n->line);
            for (int i = 0; i < n->data.print.ncount; i++) {
                struct AST_NODE *e = n->data.print.args[i];
                x64_gen_expr(e);
                EMIT(0xE8);
                emit_patch(0, type_is_str_arg(e) ? out_print_str_label : out_print_label);
            }
            break;
        case NODE_BLOCK: {
            int sn = sym_nlocal, so = sym_frame_off;
            for (int i = 0; i < n->data.block.count; i++) x64_gen_stmt(n->data.block.stmts[i]);
            sym_nlocal = sn; sym_frame_off = so;
            break;
        }
        case NODE_IF: {
            int lab_else = emit_new_label(), lab_end = emit_new_label();
            emit_jcc(x64_gen_cond(n->data.if_node.cond), lab_else);
            int sn = sym_nlocal, so = sym_frame_off;
            x64_gen_stmt(n->data.if_node.then);
            sym_nlocal = sn; sym_frame_off = so;
            emit_jmp(lab_end);
            emit_put_label(lab_else);
            if (n->data.if_node.else_) {
                x64_gen_stmt(n->data.if_node.else_);
                sym_nlocal = sn; sym_frame_off = so;
            }
            emit_put_label(lab_end);
            break;
        }
        case NODE_WHILE: {
            int lab_start = emit_new_label(), lab_end = emit_new_label();
            if (sym_nloop >= 64) die("loops too deep", n->line);
            sym_break_labels[sym_nloop] = lab_end; sym_cont_labels[sym_nloop] = lab_start; sym_nloop++;
            emit_put_label(lab_start);
            emit_jcc(x64_gen_cond(n->data.while_node.cond), lab_end);
            int sn = sym_nlocal, so = sym_frame_off;
            x64_gen_stmt(n->data.while_node.body);
            sym_nlocal = sn; sym_frame_off = so;
            emit_jmp(lab_start);
            emit_put_label(lab_end);
            sym_nloop--;
            break;
        }
        case NODE_FOR: {
            if (sym_nloop >= 64) die("loops too deep", n->line);
            int sn = sym_nlocal, so = sym_frame_off;
            int lab_body = emit_new_label(), lab_cont = emit_new_label(), lab_test = emit_new_label(), lab_end = emit_new_label();
            if (n->data.for_node.init) x64_gen_stmt(n->data.for_node.init);
            sym_break_labels[sym_nloop] = lab_end; sym_cont_labels[sym_nloop] = lab_cont; sym_nloop++;
            emit_jmp(lab_test);
            emit_put_label(lab_body);
            x64_gen_stmt(n->data.for_node.body);
            emit_put_label(lab_cont);
            if (n->data.for_node.inc) x64_gen_expr(n->data.for_node.inc);
            emit_put_label(lab_test);
            if (n->data.for_node.cond) { emit_jcc(x64_gen_cond(n->data.for_node.cond), lab_end); emit_jmp(lab_body); }
            else emit_jmp(lab_body);
            emit_put_label(lab_end);
            sym_nloop--;
            sym_nlocal = sn; sym_frame_off = so;
            break;
        }
        case NODE_SWITCH: {
            struct AST_NODE **arms = n->data.switch_node.arms;
            int na = n->data.switch_node.narms;
            if (sym_nloop >= 64) die("nesting too deep", n->line);
            int sn = sym_nlocal, so = sym_frame_off;
            int lab_end = emit_new_label(), def_lab = lab_end;
            int alab[na > 0 ? na : 1];
            int nc = 0; long lo = 0, hi = 0;
            for (int k = 0; k < na; k++) {
                alab[k] = emit_new_label();
                if (arms[k]->data.case_arm.is_default) def_lab = alab[k];
                else { long v = arms[k]->data.case_arm.val; if (!nc) { lo = hi = v; } else { if (v < lo) lo = v; if (v > hi) hi = v; } nc++; }
            }
            long span = hi - lo;
            int use_table = nc >= 4 && span <= 512 && span <= 4 * nc;
            sym_break_labels[sym_nloop] = lab_end; sym_cont_labels[sym_nloop] = lab_end; sym_nloop++;
            if (use_table) {
                int tbl = emit_new_label();
                x64_gen_expr(n->data.switch_node.expr);
                EMIT(0x48, 0x89, 0xC7);
                EMIT(0x48, 0x81, 0xEF); emit_imm(lo, 4);
                EMIT(0x48, 0x81, 0xFF); emit_imm(span, 4);
                emit_jcc(0x87, def_lab);
                EMIT(0x48, 0x8D, 0x15); emit_patch(0, tbl);
                EMIT(0x48, 0x63, 0x04, 0xBA);
                EMIT(0x48, 0x01, 0xD0);
                EMIT(0xFF, 0xE0);
                for (int k = 0; k < na; k++) {
                    emit_put_label(alab[k]);
                    struct AST_NODE *b = arms[k]->data.case_arm.blk;
                    for (int i = 0; i < b->data.block.count; i++) x64_gen_stmt(b->data.block.stmts[i]);
                }
                emit_jmp(lab_end);
                emit_put_label(tbl);
                for (long i = 0; i <= span; i++) {
                    int t = def_lab;
                    for (int k = 0; k < na; k++)
                        if (!arms[k]->data.case_arm.is_default && arms[k]->data.case_arm.val == lo + i) { t = alab[k]; break; }
                    int idx = emit_npatch;
                    emit_patch(3, t);
                    emit_patch_base[idx] = tbl;
                }
            } else {
                x64_gen_expr(n->data.switch_node.expr);
                for (int k = 0; k < na; k++) {
                    if (arms[k]->data.case_arm.is_default) continue;
                    x64_emit_cmp_imm(arms[k]->data.case_arm.val);
                    emit_jcc(0x84, alab[k]);
                }
                emit_jmp(def_lab);
                for (int k = 0; k < na; k++) {
                    emit_put_label(alab[k]);
                    struct AST_NODE *b = arms[k]->data.case_arm.blk;
                    for (int i = 0; i < b->data.block.count; i++) x64_gen_stmt(b->data.block.stmts[i]);
                }
            }
            sym_nloop--;
            emit_put_label(lab_end);
            sym_nlocal = sn; sym_frame_off = so;
            break;
        }
        case NODE_BREAK:
            if (!sym_nloop) die("break outside loop", n->line);
            emit_jmp(sym_break_labels[sym_nloop - 1]);
            break;
        case NODE_CONTINUE:
            if (!sym_nloop) die("continue outside loop", n->line);
            emit_jmp(sym_cont_labels[sym_nloop - 1]);
            break;
        case NODE_RETURN:
            x64_gen_expr(n->data.return_node.value);
            if (out_naked) EMIT(0xC3);
            else EMIT(0xC9, 0xC3);
            break;
        default:
            x64_gen_expr(n);
            break;
    }
}

static int x64_emit_prologue(void) {
    EMIT(0x55, 0x48,0x89,0xE5, 0x48,0x81,0xEC);
    int p = emit_len;
    emit_imm(0, 4);
    return p;
}

static void x64_patch_prologue(int p) {
    int need = (-sym_frame_min + 32 + 15) & ~15;
    if (need < 32) need = 32;
    *(int32_t *)(emit_buf + p) = need;
}

static int x64_needs_frame(struct AST_NODE *n) {
    if (!n) return 0;
    if (n->type == NODE_LET) return 1;
    if (n->type == NODE_BLOCK) {
        for (int i = 0; i < n->data.block.count; i++)
            if (x64_needs_frame(n->data.block.stmts[i])) return 1;
        return 0;
    }
    if (n->type == NODE_IF) return x64_needs_frame(n->data.if_node.then) || x64_needs_frame(n->data.if_node.else_);
    if (n->type == NODE_WHILE) return x64_needs_frame(n->data.while_node.body);
    if (n->type == NODE_FOR) return (n->data.for_node.init && x64_needs_frame(n->data.for_node.init)) || x64_needs_frame(n->data.for_node.body);
    if (n->type == NODE_SWITCH) {
        for (int i = 0; i < n->data.switch_node.narms; i++)
            if (x64_needs_frame(n->data.switch_node.arms[i]->data.case_arm.blk)) return 1;
        return 0;
    }
    return 0;
}

#define X64_GREG_NREG 4
static int x64_gregs[256], x64_greg_bad[256];

static void x64_scan_node(struct AST_NODE *n, int w) {
    if (!n || w <= 0) return;
    switch (n->type) {
        case NODE_VARIABLE: {
            struct SYM_GLOBAL *g = sym_global_find(n->data.variable.name);
            if (g) x64_gregs[g - SYM_GLOBALS] += w;
            break;
        }
        case NODE_ADDR: {
            struct AST_NODE *v = n->data.unary.value;
            if (v->type == NODE_VARIABLE) {
                struct SYM_GLOBAL *g = sym_global_find(v->data.variable.name);
                if (g) x64_greg_bad[g - SYM_GLOBALS] = 1;
            } else x64_scan_node(v, w);
            break;
        }
        case NODE_NUMBER: case NODE_STR: case NODE_SIZEOF: break;
        case NODE_NOT: case NODE_DEREF: case NODE_BNOT:
            x64_scan_node(n->data.unary.value, w);
            break;
        case NODE_BINARY:
            x64_scan_node(n->data.binary.left, w);
            x64_scan_node(n->data.binary.right, w);
            break;
        case NODE_ASSIGN:
            x64_scan_node(n->data.assign.lhs, w);
            x64_scan_node(n->data.assign.rhs, w);
            break;
        case NODE_LET:    x64_scan_node(n->data.let.value, w); break;
        case NODE_PRINT:
            for (int i = 0; i < n->data.print.ncount; i++) x64_scan_node(n->data.print.args[i], w);
            break;
        case NODE_RETURN: x64_scan_node(n->data.return_node.value, w); break;
        case NODE_INDEX:
            x64_scan_node(n->data.index.base, w);
            x64_scan_node(n->data.index.index, w);
            break;
        case NODE_MEMBER:
            x64_scan_node(n->data.member.base, w);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) x64_scan_node(n->data.call.args[i], w);
            break;
        case NODE_BLOCK:
            for (int i = 0; i < n->data.block.count; i++) x64_scan_node(n->data.block.stmts[i], w);
            break;
        case NODE_IF:
            x64_scan_node(n->data.if_node.cond, w);
            x64_scan_node(n->data.if_node.then, w);
            x64_scan_node(n->data.if_node.else_, w);
            break;
        case NODE_WHILE:
            x64_scan_node(n->data.while_node.cond, w * 8);
            x64_scan_node(n->data.while_node.body, w * 8);
            break;
        case NODE_FOR:
            x64_scan_node(n->data.for_node.init, w);
            x64_scan_node(n->data.for_node.cond, w * 8);
            x64_scan_node(n->data.for_node.inc, w * 8);
            x64_scan_node(n->data.for_node.body, w * 8);
            break;
        case NODE_SWITCH:
            x64_scan_node(n->data.switch_node.expr, w);
            for (int i = 0; i < n->data.switch_node.narms; i++)
                x64_scan_node(n->data.switch_node.arms[i]->data.case_arm.blk, w);
            break;
        case NODE_FUNCTION: x64_scan_node(n->data.function.body, w); break;
        default: break;
    }
}

static void x64_pick_glob_regs(struct AST_NODE *root) {
    static const int RV[X64_GREG_NREG] = { 12, 13, 14, 15 };
    x64_scan_node(root, 1);
    for (int k = 0; k < X64_GREG_NREG; k++) {
        int best = -1;
        for (int i = 0; i < sym_nglobal; i++) {
            if (SYM_GLOBALS[i].reg || x64_greg_bad[i] || !x64_gregs[i]) continue;
            if (SYM_GLOBALS[i].ty->kind == 2 || SYM_GLOBALS[i].ty->sz != 8) continue;
            if (best < 0 || x64_gregs[i] > x64_gregs[best]) best = i;
        }
        if (best < 0) return;
        SYM_GLOBALS[best].reg = RV[k];
        if (getenv("LGC_DUMP_GREG"))
            fprintf(stderr, "[greg] %-12s -> r%-2d weight=%-6d off=%d\n",
                    SYM_GLOBALS[best].name, RV[k], x64_gregs[best], SYM_GLOBALS[best].off);
    }
}

static void x64_emit_entry(struct AST_NODE *root) {
    for (int i = 0; i < sym_nglobal; i++)
        if (SYM_GLOBALS[i].reg) x64_greg_zero(SYM_GLOBALS[i].reg);
    if (!out_freestanding) {
        for (int i = 0; i < 8; i++) {
            char nm[8];
            sprintf(nm, "argv%d", i + 1);
            struct SYM_GLOBAL *a = sym_global_find(nm);
            if (!a) continue;
            EMIT(0x48, 0x8B, 0x44, 0x24, (uint8_t)(0x10 + 8 * i));
            if (a->reg) { x64_greg_store_rax(a->reg); continue; }
            EMIT(0x48, 0x89, 0x05);
            emit_patch(2, a->off);
        }
    }

    int toplet = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type != NODE_FUNCTION && n->type != NODE_LET && x64_needs_frame(n)) toplet = 1;
    }
    int epp = 0;
    if (toplet) epp = x64_emit_prologue();
    sym_nlocal = 0; sym_frame_off = 0; sym_frame_min = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION) continue;
        if (n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
        if (n->type == NODE_LET) {
            if (!n->data.let.value) continue;
            struct SYM_GLOBAL *g = sym_global_find(n->data.let.name);
            x64_gen_expr(n->data.let.value);
            if (g && g->reg) { x64_greg_store_rax(g->reg); continue; }
            EMIT(0x50);
            EMIT(0x48, 0x8D, 0x1D);
            emit_patch(2, g->off);
            EMIT(0x58);
            if (type_is_char(g->ty)) EMIT(0x88, 0x03);
            else EMIT(0x48, 0x89, 0x03);
            continue;
        }
        x64_gen_stmt(n);
    }
    int mi = sym_func_find(out_entry_name ? out_entry_name : "main");
    if (mi >= 0) {
        EMIT(0xE8); emit_patch(0, SYM_FUNCS[mi].lab);
        if (out_freestanding) EMIT(0xEB, 0xFE);
        else if (emit_is_pe) {
            EMIT(0x48, 0x89, 0xC1);
            emit_call_iat(2);
        } else {
            EMIT(0x48, 0x89, 0xC7);
            x64_mov_imm(60);
            EMIT(0x0F, 0x05);
        }
    } else if (out_freestanding) {
        EMIT(0xEB, 0xFE);
    } else if (emit_is_pe) {
        EMIT(0x31, 0xC9);
        emit_call_iat(2);
    } else {
        x64_mov_imm(60);
        EMIT(0x31, 0xFF);
        EMIT(0x0F, 0x05);
    }
    if (toplet) x64_patch_prologue(epp);
}

static void x64_generate(struct AST_NODE *root) {
    out_bin_fmt = (out_format == FMT_BIN);
    emit_len = 0;
    sym_global_hash_build();
    sym_func_hash_build();
    if (out_raw_mode) {
        emit_lit_label = emit_new_label();
        for (int i = 0; i < root->data.block.count; i++) {
            struct AST_NODE *n = root->data.block.stmts[i];
            if (n->type == NODE_FUNCTION) continue;
            if (n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
            x64_gen_stmt(n);
        }
        emit_entry_off = 0;
        emit_put_label(emit_lit_label);
        emit_raw_apply();
        emit_apply_patches();
        return;
    }
    if (!out_freestanding) {
        out_print_label = emit_new_label(); emit_put_label(out_print_label);
        if (emit_is_pe) x64_emit_print_pe(); else x64_emit_print_elf();
        out_print_str_label = emit_new_label(); emit_put_label(out_print_str_label);
        if (emit_is_pe) x64_emit_print_str_pe(); else x64_emit_print_str_elf();
    }
    emit_lit_label = emit_new_label();

    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        if (sym_nglobal >= (int)(sizeof SYM_GLOBALS / sizeof *SYM_GLOBALS)) die("too many globals", n->line);
        SYM_GLOBALS[sym_nglobal] = (typeof(SYM_GLOBALS[0])){ n->data.let.name, n->data.let.ty, sym_gsize, 0 };
        sym_gsize += type_size(n->data.let.ty);
        sym_nglobal++;
    }
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        if (sym_nfunc >= (int)(sizeof SYM_FUNCS / sizeof *SYM_FUNCS)) die("too many functions", f->line);
        SYM_FUNCS[sym_nfunc] = (typeof(SYM_FUNCS[0])){ f->data.function.name, emit_new_label(), f->data.function.pcount };
        sym_nfunc++;
    }
    sym_global_hash_build();
    sym_func_hash_build();
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_EXTERN_FUNC) {
            int f = sym_func_find(n->data.extfn.name);
            if (f < 0) die("extern func has no definition", n->line);
            if (SYM_FUNCS[f].params != n->data.extfn.pcount) die("extern func arity mismatch", n->line);
        } else if (n->type == NODE_EXTERN_GLOB) {
            if (!sym_global_find(n->data.extgl.name)) die("extern let has no definition", n->line);
        }
    }

    if (!out_freestanding) x64_pick_glob_regs(root);

    if (out_bin_fmt) { emit_entry_off = emit_len; x64_emit_entry(root); }

    if (out_boot_mode) {
        out_print_label = emit_new_label();
        emit_put_label(out_print_label);
        x64_emit_print_bare();
        out_print_str_label = emit_new_label();
        emit_put_label(out_print_str_label);
        x64_emit_print_str_bare();
    }

    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *f = root->data.block.stmts[i];
        if (f->type != NODE_FUNCTION) continue;
        emit_put_label(SYM_FUNCS[sym_func_find(f->data.function.name)].lab);
        int pp = -1;
        out_naked = f->data.function.naked;
        if (!out_naked) pp = x64_emit_prologue();
        sym_nlocal = 0; sym_frame_off = 0; sym_frame_min = 0;
        if (f->data.function.pcount > 0 && !out_naked) {
            EMIT(0x48, 0x89, 0xF8);
            int off = sym_local_add(f->data.function.params[0], &TYPE_INT)->off;
            EMIT(0x48, 0x89); x64_rbp_disp(0, off);
        }
        if (f->data.function.pcount > 0 && !out_naked)
            for (int k = 1; k < f->data.function.pcount; k++) {
                int off = sym_local_add(f->data.function.params[k], &TYPE_INT)->off;
                EMIT(0x48, 0x8B); x64_rbp_disp(0, 16 + 8 * (k - 1));
                EMIT(0x48, 0x89); x64_rbp_disp(0, off);
            }
        x64_gen_stmt(f->data.function.body);
        if (!out_naked) { EMIT(0xC9, 0xC3); x64_patch_prologue(pp); }
        out_naked = 0;
    }

    if (!out_bin_fmt) { emit_entry_off = emit_len; x64_emit_entry(root); }

    emit_put_label(emit_lit_label);
    if (parse_nlit) { memcpy(emit_buf + emit_len, PARSE_LITS, parse_nlit); emit_len += parse_nlit; }
    emit_shrink_relayout();
    emit_pcb = (EMIT_PE_SECT_SIZE + 15) & ~15;
    if (emit_is_pe) {
        emit_apply_patches();
        uint32_t imp_rva = emit_pcb + ((emit_len + 15) & ~15);
        for (int i = 0; i < emit_niat; i++) {
            int pos = EMIT_IAT_PATCH[i] >> 2, slot = EMIT_IAT_PATCH[i] & 3;
            *(int32_t *)(emit_buf + pos) = imp_rva + 72 + (slot << 3) - (emit_pcb + pos + 4);
        }
    } else {
        emit_apply_patches();
    }
}

static struct AST_NODE *ast_number(long v, int line) {
    struct AST_NODE *n = ast_new(NODE_NUMBER, line);
    n->data.number.value = v;
    return n;
}

static struct AST_NODE *ast_variable(const char *name, int line) {
    struct AST_NODE *n = ast_new(NODE_VARIABLE, line);
    n->data.variable.name = (char *)name;
    return n;
}

static struct AST_NODE *ast_let(const char *name, struct AST_NODE *val, int line) {
    struct AST_NODE *n = ast_new(NODE_LET, line);
    n->data.let.name = (char *)name;
    n->data.let.ty = &TYPE_INT;
    n->data.let.value = val;
    return n;
}

static int opt_has_side_effect(struct AST_NODE *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_ASSIGN:
        case NODE_CALL:
            return 1;
        case NODE_BINARY:
            return opt_has_side_effect(n->data.binary.left) || opt_has_side_effect(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT: case NODE_ADDR: case NODE_DEREF:
            return opt_has_side_effect(n->data.unary.value);
        case NODE_INDEX:
            return opt_has_side_effect(n->data.index.base) || opt_has_side_effect(n->data.index.index);
        case NODE_MEMBER:
            return opt_has_side_effect(n->data.member.base);
        default:
            return 0;
    }
}

static int opt_is_pure(struct AST_NODE *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_NUMBER:
        case NODE_VARIABLE:
            return 1;
        case NODE_BINARY:
            if (n->data.binary.op == BIN_DIV || n->data.binary.op == BIN_MOD) return 0;
            return opt_is_pure(n->data.binary.left) && opt_is_pure(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT:
            return opt_is_pure(n->data.unary.value);
        default:
            return 0;
    }
}

static int opt_ast_equal(struct AST_NODE *a, struct AST_NODE *b) {
    if (a == b) return 1;
    if (!a || !b || a->type != b->type) return 0;
    switch (a->type) {
        case NODE_NUMBER: return a->data.number.value == b->data.number.value;
        case NODE_VARIABLE: return !strcmp(a->data.variable.name, b->data.variable.name);
        case NODE_BINARY:
            return a->data.binary.op == b->data.binary.op &&
                   opt_ast_equal(a->data.binary.left, b->data.binary.left) &&
                   opt_ast_equal(a->data.binary.right, b->data.binary.right);
        case NODE_NOT: case NODE_BNOT:
            return opt_ast_equal(a->data.unary.value, b->data.unary.value);
        default: return 0;
    }
}

static struct AST_NODE *opt_fold_binary(struct AST_NODE *n) {
    enum BIN_OP op = n->data.binary.op;
    struct AST_NODE *l = n->data.binary.left, *r = n->data.binary.right;
    int lc = l->type == NODE_NUMBER, rc = r->type == NODE_NUMBER;
    long lv = lc ? l->data.number.value : 0, rv = rc ? r->data.number.value : 0;
    if (lc && rc) return ast_binary(op, l, r, n->line);
    switch (op) {
        case BIN_ADD:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case BIN_SUB:
            if (rc && rv == 0) return l;
            break;
        case BIN_MUL:
            if (lc && lv == 0) return ast_number(0, n->line);
            if (rc && rv == 0) return ast_number(0, n->line);
            if (lc && lv == 1) return r;
            if (rc && rv == 1) return l;
            if (rc && rv > 0 && (rv & (rv - 1)) == 0)
                return ast_binary(BIN_SHL, l, ast_number(__builtin_ctzll((unsigned long long)rv), n->line), n->line);
            if (lc && lv > 0 && (lv & (lv - 1)) == 0)
                return ast_binary(BIN_SHL, r, ast_number(__builtin_ctzll((unsigned long long)lv), n->line), n->line);
            break;
        case BIN_DIV:
            if (rc && rv == 1) return l;
            break;
        case BIN_MOD:
            if (rc && rv == 1) return ast_number(0, n->line);
            break;
        case BIN_BOR:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case BIN_BAND:
            if (lc && lv == -1) return r;
            if (rc && rv == -1) return l;
            break;
        case BIN_BXOR:
            if (lc && lv == 0) return r;
            if (rc && rv == 0) return l;
            break;
        case BIN_SHL:
        case BIN_SHR:
            if (rc && rv == 0) return l;
            break;
        default:
            break;
    }
    if (opt_ast_equal(l, r) && opt_is_pure(l)) {
        if (op == BIN_BAND || op == BIN_BOR) return l;
        if (op == BIN_BXOR || op == BIN_SUB) return ast_number(0, n->line);
        if (op == BIN_EQ || op == BIN_LE || op == BIN_GE) return ast_number(1, n->line);
        if (op == BIN_NE || op == BIN_LT || op == BIN_GT) return ast_number(0, n->line);
    }
    return n;
}

static struct AST_NODE *opt_fold_expr(struct AST_NODE *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_BINARY:
            n->data.binary.left = opt_fold_expr(n->data.binary.left);
            n->data.binary.right = opt_fold_expr(n->data.binary.right);
            return opt_fold_binary(n);
        case NODE_NOT:
            n->data.unary.value = opt_fold_expr(n->data.unary.value);
            if (n->data.unary.value->type == NODE_NUMBER)
                return ast_number(!n->data.unary.value->data.number.value, n->line);
            return n;
        case NODE_BNOT:
            n->data.unary.value = opt_fold_expr(n->data.unary.value);
            if (n->data.unary.value->type == NODE_NUMBER)
                return ast_number(~n->data.unary.value->data.number.value, n->line);
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

static void opt_fold_block(struct AST_NODE *b);
static void opt_fold_stmt(struct AST_NODE **slot);

static void opt_fold_stmt(struct AST_NODE **slot) {
    struct AST_NODE *n = *slot;
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

static void opt_fold_block(struct AST_NODE *b) {
    if (!b) return;
    for (int i = 0; i < b->data.block.count; i++)
        opt_fold_stmt(&b->data.block.stmts[i]);
}

#define OPT_SCOPE_CAP 65536
static struct { char *name; struct AST_NODE *let; } OPT_SCOPE[OPT_SCOPE_CAP];
static int opt_scope_n;
static void opt_scope_push(void) {
    if (opt_scope_n + 1 >= OPT_SCOPE_CAP) die("scope too deep", 0);
    OPT_SCOPE[opt_scope_n].name = NULL; OPT_SCOPE[opt_scope_n].let = NULL; opt_scope_n++;
}
static void opt_scope_pop(void) {
    while (opt_scope_n > 0 && OPT_SCOPE[opt_scope_n - 1].let) opt_scope_n--;
    if (opt_scope_n > 0) opt_scope_n--;
}
static void opt_scope_add(char *name, struct AST_NODE *let) {
    if (opt_scope_n >= OPT_SCOPE_CAP) die("scope too deep", 0);
    OPT_SCOPE[opt_scope_n].name = name; OPT_SCOPE[opt_scope_n].let = let; opt_scope_n++;
}
static struct AST_NODE *opt_scope_find(const char *name) {
    for (int i = opt_scope_n - 1; i >= 0; i--) {
        if (!OPT_SCOPE[i].let) continue;
        if (!strcmp(OPT_SCOPE[i].name, name)) return OPT_SCOPE[i].let;
    }
    return NULL;
}

#define OPT_NODE_IDX(n) ((int)((n) - AST_ARENA))
static struct { signed char kind; unsigned char flags; long value; struct AST_NODE *src; } OPT_INFO[AST_CAP];

static char *OPT_GLOBAL_NAME[256]; static int opt_nglobal;
static long OPT_GLOBAL_VALUE[256];
static struct TYPE *OPT_GLOBAL_TYPE[256];
static unsigned char OPT_GLOBAL_CONST[256], OPT_GLOBAL_ASSIGNED[256], OPT_GLOBAL_ADDR[256];
static int opt_global_index(const char *name) {
    for (int i = 0; i < opt_nglobal; i++) if (!strcmp(OPT_GLOBAL_NAME[i], name)) return i;
    return -1;
}

static void opt_analyze_expr(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_VARIABLE: break;
        case NODE_BINARY:
            opt_analyze_expr(n->data.binary.left);
            opt_analyze_expr(n->data.binary.right);
            break;
        case NODE_ASSIGN:
            if (n->data.assign.lhs->type == NODE_VARIABLE) {
                struct AST_NODE *L = opt_scope_find(n->data.assign.lhs->data.variable.name);
                if (L) OPT_INFO[OPT_NODE_IDX(L)].flags |= 1;
                else { int g = opt_global_index(n->data.assign.lhs->data.variable.name); if (g >= 0) OPT_GLOBAL_ASSIGNED[g] = 1; }
            }
            opt_analyze_expr(n->data.assign.lhs);
            opt_analyze_expr(n->data.assign.rhs);
            break;
        case NODE_ADDR:
            if (n->data.unary.value->type == NODE_VARIABLE) {
                struct AST_NODE *L = opt_scope_find(n->data.unary.value->data.variable.name);
                if (L) OPT_INFO[OPT_NODE_IDX(L)].flags |= 2;
                else { int g = opt_global_index(n->data.unary.value->data.variable.name); if (g >= 0) OPT_GLOBAL_ADDR[g] = 1; }
            } else opt_analyze_expr(n->data.unary.value);
            break;
        case NODE_NOT: case NODE_BNOT: case NODE_DEREF:
            opt_analyze_expr(n->data.unary.value);
            break;
        case NODE_INDEX:
            opt_analyze_expr(n->data.index.base);
            opt_analyze_expr(n->data.index.index);
            break;
        case NODE_MEMBER:
            opt_analyze_expr(n->data.member.base);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) opt_analyze_expr(n->data.call.args[i]);
            break;
        default: break;
    }
}

static void opt_analyze_stmt(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            opt_analyze_expr(n->data.let.value);
            if (n->data.let.value && n->data.let.value->type == NODE_NUMBER) {
                OPT_INFO[OPT_NODE_IDX(n)].kind = 1; OPT_INFO[OPT_NODE_IDX(n)].value = n->data.let.value->data.number.value;
            } else if (n->data.let.value && n->data.let.value->type == NODE_VARIABLE) {
                struct AST_NODE *SL = opt_scope_find(n->data.let.value->data.variable.name);
                if (SL) { OPT_INFO[OPT_NODE_IDX(n)].kind = 2; OPT_INFO[OPT_NODE_IDX(n)].src = SL; }
            }
            opt_scope_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            opt_scope_push();
            for (int i = 0; i < n->data.block.count; i++) opt_analyze_stmt(n->data.block.stmts[i]);
            opt_scope_pop();
            break;
        case NODE_IF:
            opt_analyze_expr(n->data.if_node.cond);
            opt_scope_push(); opt_analyze_stmt(n->data.if_node.then); opt_scope_pop();
            opt_scope_push(); opt_analyze_stmt(n->data.if_node.else_); opt_scope_pop();
            break;
        case NODE_WHILE:
            opt_analyze_expr(n->data.while_node.cond);
            opt_scope_push(); opt_analyze_stmt(n->data.while_node.body); opt_scope_pop();
            break;
        case NODE_FOR:
            opt_scope_push();
            opt_analyze_stmt(n->data.for_node.init);
            opt_analyze_expr(n->data.for_node.cond);
            opt_analyze_expr(n->data.for_node.inc);
            opt_analyze_stmt(n->data.for_node.body);
            opt_scope_pop();
            break;
        case NODE_SWITCH:
            opt_analyze_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                opt_scope_push(); opt_analyze_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); opt_scope_pop();
            }
            break;
        case NODE_RETURN: opt_analyze_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) opt_analyze_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: opt_scope_n = 0; opt_analyze_stmt(n->data.function.body); break;
        default: opt_analyze_expr(n); break;
    }
}

static void opt_analyze_program(struct AST_NODE *root) {
    opt_nglobal = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        OPT_GLOBAL_NAME[opt_nglobal] = n->data.let.name;
        OPT_GLOBAL_TYPE[opt_nglobal] = n->data.let.ty;
        if (n->data.let.value && n->data.let.value->type == NODE_NUMBER) {
            OPT_GLOBAL_VALUE[opt_nglobal] = n->data.let.value->data.number.value; OPT_GLOBAL_CONST[opt_nglobal] = 1;
        } else OPT_GLOBAL_CONST[opt_nglobal] = 0;
        OPT_GLOBAL_ASSIGNED[opt_nglobal] = 0; OPT_GLOBAL_ADDR[opt_nglobal] = 0;
        opt_nglobal++;
    }
    opt_scope_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) opt_analyze_expr(n->data.let.value);
        else { opt_scope_n = 0; opt_analyze_stmt(n); }
    }
    opt_scope_n = 0;
}

static struct AST_NODE *opt_propagate_expr(struct AST_NODE *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_VARIABLE: {
            struct AST_NODE *L = opt_scope_find(n->data.variable.name);
            if (L && L->data.let.ty && L->data.let.ty->kind == 0 &&
                !(OPT_INFO[OPT_NODE_IDX(L)].flags & 3) && OPT_INFO[OPT_NODE_IDX(L)].kind) {
                struct AST_NODE *cur = L;
                while (cur && OPT_INFO[OPT_NODE_IDX(cur)].kind == 2 && !(OPT_INFO[OPT_NODE_IDX(cur)].flags & 3) && OPT_INFO[OPT_NODE_IDX(cur)].src)
                    cur = OPT_INFO[OPT_NODE_IDX(cur)].src;
                if (cur && OPT_INFO[OPT_NODE_IDX(cur)].kind == 1 && !(OPT_INFO[OPT_NODE_IDX(cur)].flags & 3)) {
                    n->type = NODE_NUMBER;
                    n->data.number.value = OPT_INFO[OPT_NODE_IDX(cur)].value;
                    return n;
                }
            } else if (!L) {
                int g = opt_global_index(n->data.variable.name);
                if (g >= 0 && OPT_GLOBAL_CONST[g] && OPT_GLOBAL_TYPE[g] && OPT_GLOBAL_TYPE[g]->kind == 0 && !OPT_GLOBAL_ASSIGNED[g] && !OPT_GLOBAL_ADDR[g] && !out_freestanding) {
                    n->type = NODE_NUMBER;
                    n->data.number.value = OPT_GLOBAL_VALUE[g];
                    return n;
                }
            }
            return n;
        }
        case NODE_BINARY:
            n->data.binary.left = opt_propagate_expr(n->data.binary.left);
            n->data.binary.right = opt_propagate_expr(n->data.binary.right);
            return n;
        case NODE_NOT: case NODE_BNOT: case NODE_DEREF:
            n->data.unary.value = opt_propagate_expr(n->data.unary.value);
            return n;
        case NODE_ADDR: case NODE_SIZEOF:
            return n;
        case NODE_INDEX:
            n->data.index.base = opt_propagate_expr(n->data.index.base);
            n->data.index.index = opt_propagate_expr(n->data.index.index);
            return n;
        case NODE_MEMBER:
            n->data.member.base = opt_propagate_expr(n->data.member.base);
            return n;
        case NODE_ASSIGN:
            n->data.assign.rhs = opt_propagate_expr(n->data.assign.rhs);
            return n;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) n->data.call.args[i] = opt_propagate_expr(n->data.call.args[i]);
            return n;
        default:
            return n;
    }
}

static void opt_propagate_stmt(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            if (n->data.let.value) n->data.let.value = opt_propagate_expr(n->data.let.value);
            opt_scope_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            opt_scope_push();
            for (int i = 0; i < n->data.block.count; i++) opt_propagate_stmt(n->data.block.stmts[i]);
            opt_scope_pop();
            break;
        case NODE_IF:
            n->data.if_node.cond = opt_propagate_expr(n->data.if_node.cond);
            opt_scope_push(); opt_propagate_stmt(n->data.if_node.then); opt_scope_pop();
            opt_scope_push(); opt_propagate_stmt(n->data.if_node.else_); opt_scope_pop();
            break;
        case NODE_WHILE:
            n->data.while_node.cond = opt_propagate_expr(n->data.while_node.cond);
            opt_scope_push(); opt_propagate_stmt(n->data.while_node.body); opt_scope_pop();
            break;
        case NODE_FOR:
            opt_scope_push();
            opt_propagate_stmt(n->data.for_node.init);
            if (n->data.for_node.cond) n->data.for_node.cond = opt_propagate_expr(n->data.for_node.cond);
            if (n->data.for_node.inc) n->data.for_node.inc = opt_propagate_expr(n->data.for_node.inc);
            opt_propagate_stmt(n->data.for_node.body);
            opt_scope_pop();
            break;
        case NODE_SWITCH:
            n->data.switch_node.expr = opt_propagate_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                opt_scope_push(); opt_propagate_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); opt_scope_pop();
            }
            break;
        case NODE_RETURN: n->data.return_node.value = opt_propagate_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) n->data.print.args[i] = opt_propagate_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: opt_scope_n = 0; opt_propagate_stmt(n->data.function.body); break;
        default: opt_propagate_expr(n); break;
    }
}

static void opt_propagate_program(struct AST_NODE *root) {
    opt_scope_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) {
            if (n->data.let.value) n->data.let.value = opt_propagate_expr(n->data.let.value);
        } else { opt_scope_n = 0; opt_propagate_stmt(n); }
    }
    opt_scope_n = 0;
}

static void opt_branch_block(struct AST_NODE *b);
static void opt_branch_norm(struct AST_NODE **slot);
static void opt_branch_recurse(struct AST_NODE *s);
static void opt_branch_emit(struct AST_NODE *s, struct AST_NODE ***out, int *n, int *cap);

static void opt_branch_emit(struct AST_NODE *s, struct AST_NODE ***out, int *n, int *cap) {
    if (!s) return;
    if (s->type == NODE_BLOCK) {
        opt_branch_block(s);
        for (int i = 0; i < s->data.block.count; i++) PUSH(*out, *n, *cap, s->data.block.stmts[i]);
    } else {
        opt_branch_recurse(s);
        PUSH(*out, *n, *cap, s);
    }
}

static void opt_branch_block(struct AST_NODE *b) {
    if (!b) return;
    struct AST_NODE **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        struct AST_NODE *s = b->data.block.stmts[i];
        if (s->type == NODE_IF && s->data.if_node.cond->type == NODE_NUMBER) {
            opt_branch_emit(s->data.if_node.cond->data.number.value ? s->data.if_node.then : s->data.if_node.else_,
                    &out, &n, &cap);
        } else if (s->type == NODE_WHILE && s->data.while_node.cond->type == NODE_NUMBER &&
                   !s->data.while_node.cond->data.number.value) {
        } else {
            opt_branch_recurse(s);
            PUSH(out, n, cap, s);
        }
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static void opt_branch_norm(struct AST_NODE **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        struct AST_NODE *b = ast_new(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    opt_branch_block(*slot);
}

static void opt_branch_recurse(struct AST_NODE *s) {
    if (!s) return;
    switch (s->type) {
        case NODE_IF: opt_branch_norm(&s->data.if_node.then); opt_branch_norm(&s->data.if_node.else_); break;
        case NODE_WHILE: opt_branch_norm(&s->data.while_node.body); break;
        case NODE_FOR: opt_branch_norm(&s->data.for_node.body); break;
        case NODE_SWITCH: for (int i = 0; i < s->data.switch_node.narms; i++) opt_branch_block(s->data.switch_node.arms[i]->data.case_arm.blk); break;
        case NODE_BLOCK: opt_branch_block(s); break;
        case NODE_FUNCTION: opt_branch_block(s->data.function.body); break;
        default: break;
    }
}

#define OPT_CSE_CAP 4096
static struct { int tag, op, l, r; long value; char *name; int vn; } OPT_CSE_TABLE[OPT_CSE_CAP];
static int opt_cse_n;
static int opt_cse_vn[AST_CAP];
static int opt_cse_count[OPT_CSE_CAP];
static char *opt_cse_tmp[OPT_CSE_CAP];
static int opt_cse_id;
static struct { char *tmp; struct AST_NODE *val; } *OPT_HOIST;
static int opt_hoist_n, opt_hoist_cap;

static void opt_hoist_add(char *tmp, struct AST_NODE *val) {
    if (opt_hoist_n >= opt_hoist_cap) { opt_hoist_cap = opt_hoist_cap ? opt_hoist_cap * 2 : 8; OPT_HOIST = realloc(OPT_HOIST, opt_hoist_cap * sizeof *OPT_HOIST); }
    OPT_HOIST[opt_hoist_n].tmp = tmp; OPT_HOIST[opt_hoist_n].val = val; opt_hoist_n++;
}

static void opt_cse_reset(void) {
    for (int i = 0; i < opt_cse_n; i++) { opt_cse_count[i] = 0; opt_cse_tmp[i] = NULL; }
    opt_cse_n = 0;
    opt_hoist_n = 0;
}

static int opt_cse_cons(int tag, int op, int l, int r, long value, const char *name) {
    for (int i = 0; i < opt_cse_n; i++) {
        if (OPT_CSE_TABLE[i].tag != tag) continue;
        if (tag == 0) { if (OPT_CSE_TABLE[i].value != value) continue; }
        else if (tag == 1) { if (strcmp(OPT_CSE_TABLE[i].name, name)) continue; }
        else if (tag == 2) { if (OPT_CSE_TABLE[i].op != op || OPT_CSE_TABLE[i].l != l || OPT_CSE_TABLE[i].r != r) continue; }
        else { if (OPT_CSE_TABLE[i].l != l) continue; }
        return OPT_CSE_TABLE[i].vn;
    }
    OPT_CSE_TABLE[opt_cse_n].tag = tag; OPT_CSE_TABLE[opt_cse_n].op = op; OPT_CSE_TABLE[opt_cse_n].l = l; OPT_CSE_TABLE[opt_cse_n].r = r;
    OPT_CSE_TABLE[opt_cse_n].value = value; OPT_CSE_TABLE[opt_cse_n].name = (char *)name; OPT_CSE_TABLE[opt_cse_n].vn = opt_cse_n;
    return opt_cse_n++;
}

static int opt_cse_number(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_NUMBER: return opt_cse_cons(0, 0, 0, 0, n->data.number.value, NULL);
        case NODE_VARIABLE: return opt_cse_cons(1, 0, 0, 0, 0, n->data.variable.name);
        case NODE_BINARY: {
            int l = opt_cse_number(n->data.binary.left);
            int r = opt_cse_number(n->data.binary.right);
            return opt_cse_cons(2, n->data.binary.op, l, r, 0, NULL);
        }
        case NODE_NOT: return opt_cse_cons(3, 0, opt_cse_number(n->data.unary.value), 0, 0, NULL);
        case NODE_BNOT: return opt_cse_cons(4, 0, opt_cse_number(n->data.unary.value), 0, 0, NULL);
        default: return -1;
    }
}

static void opt_cse_count_expr(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE: {
            int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; opt_cse_count[v]++;
            break;
        }
        case NODE_BINARY:
            opt_cse_count_expr(n->data.binary.left);
            opt_cse_count_expr(n->data.binary.right);
            { int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; opt_cse_count[v]++; }
            break;
        case NODE_NOT: case NODE_BNOT:
            opt_cse_count_expr(n->data.unary.value);
            { int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; opt_cse_count[v]++; }
            break;
        default: break;
    }
}

static struct AST_NODE *opt_cse_rewrite_expr(struct AST_NODE *n) {
    if (!n) return NULL;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE:
            return n;
        case NODE_BINARY:
            n->data.binary.left = opt_cse_rewrite_expr(n->data.binary.left);
            n->data.binary.right = opt_cse_rewrite_expr(n->data.binary.right);
            break;
        case NODE_NOT: case NODE_BNOT:
            n->data.unary.value = opt_cse_rewrite_expr(n->data.unary.value);
            break;
        default:
            return n;
    }
    int v = opt_cse_vn[OPT_NODE_IDX(n)];
    if (v >= 0 && opt_cse_count[v] >= 2) {
        if (!opt_cse_tmp[v]) {
            char buf[32];
            sprintf(buf, "$cse%d", opt_cse_id++);
            opt_cse_tmp[v] = lex_intern(buf, strlen(buf));
            opt_hoist_add(opt_cse_tmp[v], n);
        }
        return ast_variable(opt_cse_tmp[v], n->line);
    }
    return n;
}

static int opt_cse_eligible(struct AST_NODE *s) {
    switch (s->type) {
        case NODE_LET: return !s->data.let.value || opt_is_pure(s->data.let.value);
        case NODE_ASSIGN: return s->data.assign.lhs->type == NODE_VARIABLE && opt_is_pure(s->data.assign.rhs);
        case NODE_RETURN: return opt_is_pure(s->data.return_node.value);
        case NODE_PRINT:
            for (int i = 0; i < s->data.print.ncount; i++) if (!opt_is_pure(s->data.print.args[i])) return 0;
            return 1;
        default: return opt_is_pure(s);
    }
}

static void opt_cse_do_stmt(struct AST_NODE *s) {
    opt_cse_reset();
    switch (s->type) {
        case NODE_LET: if (s->data.let.value) opt_cse_count_expr(s->data.let.value); break;
        case NODE_ASSIGN: opt_cse_count_expr(s->data.assign.rhs); break;
        case NODE_RETURN: opt_cse_count_expr(s->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < s->data.print.ncount; i++) opt_cse_count_expr(s->data.print.args[i]); break;
        default: opt_cse_count_expr(s); break;
    }
    switch (s->type) {
        case NODE_LET: if (s->data.let.value) s->data.let.value = opt_cse_rewrite_expr(s->data.let.value); break;
        case NODE_ASSIGN: s->data.assign.rhs = opt_cse_rewrite_expr(s->data.assign.rhs); break;
        case NODE_RETURN: s->data.return_node.value = opt_cse_rewrite_expr(s->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < s->data.print.ncount; i++) s->data.print.args[i] = opt_cse_rewrite_expr(s->data.print.args[i]); break;
        default: opt_cse_rewrite_expr(s); break;
    }
}

static void opt_cse_block(struct AST_NODE *b);
static void opt_cse_sub(struct AST_NODE **slot);

static void opt_cse_sub(struct AST_NODE **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        struct AST_NODE *b = ast_new(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    opt_cse_block(*slot);
}

static void opt_cse_block(struct AST_NODE *b) {
    if (!b) return;
    struct AST_NODE **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        struct AST_NODE *s = b->data.block.stmts[i];
        switch (s->type) {
            case NODE_BLOCK: opt_cse_block(s); break;
            case NODE_IF: opt_cse_sub(&s->data.if_node.then); opt_cse_sub(&s->data.if_node.else_); break;
            case NODE_WHILE: opt_cse_sub(&s->data.while_node.body); break;
            case NODE_FOR: opt_cse_sub(&s->data.for_node.body); break;
            case NODE_SWITCH: for (int k = 0; k < s->data.switch_node.narms; k++) opt_cse_block(s->data.switch_node.arms[k]->data.case_arm.blk); break;
            case NODE_FUNCTION: opt_cse_block(s->data.function.body); break;
            default: if (opt_cse_eligible(s)) opt_cse_do_stmt(s); break;
        }
        for (int k = 0; k < opt_hoist_n; k++) PUSH(out, n, cap, ast_let(OPT_HOIST[k].tmp, OPT_HOIST[k].val, s->line));
        opt_hoist_n = 0;
        PUSH(out, n, cap, s);
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static unsigned char OPT_USED[AST_CAP];

static void opt_dce_count_expr(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_VARIABLE: {
            struct AST_NODE *L = opt_scope_find(n->data.variable.name);
            if (L) OPT_USED[OPT_NODE_IDX(L)] = 1;
            break;
        }
        case NODE_BINARY:
            opt_dce_count_expr(n->data.binary.left);
            opt_dce_count_expr(n->data.binary.right);
            break;
        case NODE_ASSIGN:
            opt_dce_count_expr(n->data.assign.lhs);
            opt_dce_count_expr(n->data.assign.rhs);
            break;
        case NODE_NOT: case NODE_BNOT: case NODE_ADDR: case NODE_DEREF: case NODE_SIZEOF:
            opt_dce_count_expr(n->data.unary.value);
            break;
        case NODE_INDEX:
            opt_dce_count_expr(n->data.index.base);
            opt_dce_count_expr(n->data.index.index);
            break;
        case NODE_MEMBER:
            opt_dce_count_expr(n->data.member.base);
            break;
        case NODE_CALL:
            for (int i = 0; i < n->data.call.acount; i++) opt_dce_count_expr(n->data.call.args[i]);
            break;
        default: break;
    }
}

static void opt_dce_count_stmt(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET:
            opt_dce_count_expr(n->data.let.value);
            opt_scope_add(n->data.let.name, n);
            break;
        case NODE_BLOCK:
            opt_scope_push();
            for (int i = 0; i < n->data.block.count; i++) opt_dce_count_stmt(n->data.block.stmts[i]);
            opt_scope_pop();
            break;
        case NODE_IF:
            opt_dce_count_expr(n->data.if_node.cond);
            opt_scope_push(); opt_dce_count_stmt(n->data.if_node.then); opt_scope_pop();
            opt_scope_push(); opt_dce_count_stmt(n->data.if_node.else_); opt_scope_pop();
            break;
        case NODE_WHILE:
            opt_dce_count_expr(n->data.while_node.cond);
            opt_scope_push(); opt_dce_count_stmt(n->data.while_node.body); opt_scope_pop();
            break;
        case NODE_FOR:
            opt_scope_push();
            opt_dce_count_stmt(n->data.for_node.init);
            opt_dce_count_expr(n->data.for_node.cond);
            opt_dce_count_expr(n->data.for_node.inc);
            opt_dce_count_stmt(n->data.for_node.body);
            opt_scope_pop();
            break;
        case NODE_SWITCH:
            opt_dce_count_expr(n->data.switch_node.expr);
            for (int i = 0; i < n->data.switch_node.narms; i++) {
                opt_scope_push(); opt_dce_count_stmt(n->data.switch_node.arms[i]->data.case_arm.blk); opt_scope_pop();
            }
            break;
        case NODE_RETURN: opt_dce_count_expr(n->data.return_node.value); break;
        case NODE_PRINT: for (int i = 0; i < n->data.print.ncount; i++) opt_dce_count_expr(n->data.print.args[i]); break;
        case NODE_FUNCTION: opt_scope_n = 0; opt_dce_count_stmt(n->data.function.body); break;
        default: opt_dce_count_expr(n); break;
    }
}

static void opt_dce_count_program(struct AST_NODE *root) {
    memset(OPT_USED, 0, sizeof OPT_USED);
    opt_scope_n = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) continue;
        opt_scope_n = 0;
        opt_dce_count_stmt(n);
    }
    opt_scope_n = 0;
}

static void opt_dce_block(struct AST_NODE *b, int top);
static void opt_dce_sub(struct AST_NODE **slot);
static void opt_dce_recurse(struct AST_NODE *s);

static void opt_dce_sub(struct AST_NODE **slot) {
    if (!*slot) return;
    if ((*slot)->type != NODE_BLOCK) {
        struct AST_NODE *b = ast_new(NODE_BLOCK, (*slot)->line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, *slot);
        *slot = b;
    }
    opt_dce_block(*slot, 0);
}

static void opt_dce_recurse(struct AST_NODE *s) {
    if (!s) return;
    switch (s->type) {
        case NODE_IF: opt_dce_sub(&s->data.if_node.then); opt_dce_sub(&s->data.if_node.else_); break;
        case NODE_WHILE: opt_dce_sub(&s->data.while_node.body); break;
        case NODE_FOR: {
            struct AST_NODE *ini = s->data.for_node.init;
            if (ini) {
                if (ini->type == NODE_LET) {
                    if (!OPT_USED[OPT_NODE_IDX(ini)] && !opt_has_side_effect(ini->data.let.value)) s->data.for_node.init = NULL;
                } else if (!opt_has_side_effect(ini)) {
                    s->data.for_node.init = NULL;
                }
            }
            opt_dce_sub(&s->data.for_node.body);
            break;
        }
        case NODE_SWITCH: for (int i = 0; i < s->data.switch_node.narms; i++) opt_dce_block(s->data.switch_node.arms[i]->data.case_arm.blk, 0); break;
        case NODE_BLOCK: opt_dce_block(s, 0); break;
        case NODE_FUNCTION: opt_dce_block(s->data.function.body, 0); break;
        default: break;
    }
}

static void opt_dce_block(struct AST_NODE *b, int top) {
    if (!b) return;
    struct AST_NODE **out = NULL; int n = 0, cap = 0; int terminated = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        struct AST_NODE *s = b->data.block.stmts[i];
        if (terminated) continue;
        switch (s->type) {
            case NODE_LET:
                if (top) PUSH(out, n, cap, s);
                else if (s->data.let.value) {
                    if (opt_has_side_effect(s->data.let.value) || OPT_USED[OPT_NODE_IDX(s)]) PUSH(out, n, cap, s);
                } else {
                    if (OPT_USED[OPT_NODE_IDX(s)]) PUSH(out, n, cap, s);
                }
                break;
            case NODE_IF: opt_dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_WHILE: opt_dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_FOR: opt_dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_SWITCH: opt_dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_BLOCK: opt_dce_block(s, 0); PUSH(out, n, cap, s); break;
            case NODE_FUNCTION: opt_dce_block(s->data.function.body, 0); PUSH(out, n, cap, s); break;
            case NODE_PRINT: opt_dce_recurse(s); PUSH(out, n, cap, s); break;
            case NODE_RETURN: opt_dce_recurse(s); PUSH(out, n, cap, s); terminated = 1; break;
            case NODE_BREAK: case NODE_CONTINUE: PUSH(out, n, cap, s); terminated = 1; break;
            case NODE_EXTERN_FUNC: case NODE_EXTERN_GLOB: PUSH(out, n, cap, s); break;
            default:
                if (opt_has_side_effect(s)) PUSH(out, n, cap, s);
                break;
        }
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static int opt_tco_id;

static int tco_is_tail(struct AST_NODE *n, const char *fname, int pcount) {
    if (!n || n->type != NODE_CALL || strcmp(n->data.call.name, fname)) return 0;
    if (n->data.call.acount != pcount) return 0;
    for (int i = 0; i < n->data.call.acount; i++)
        if (!opt_is_pure(n->data.call.args[i])) return 0;
    return 1;
}

static struct AST_NODE *tco_replace(struct AST_NODE *call, char **params, int pcount, int line) {
    struct AST_NODE *b = ast_new(NODE_BLOCK, line);
    char *tnames[64];
    for (int i = 0; i < pcount; i++) {
        char buf[32];
        sprintf(buf, "$tco%d", opt_tco_id++);
        tnames[i] = lex_intern(buf, strlen(buf));
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, ast_let(tnames[i], call->data.call.args[i], line));
    }
    for (int i = 0; i < pcount; i++) {
        struct AST_NODE *as = ast_new(NODE_ASSIGN, line);
        as->data.assign.lhs = ast_variable(params[i], line);
        as->data.assign.cop = 0;
        as->data.assign.rhs = ast_variable(tnames[i], line);
        PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, as);
    }
    PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, ast_new(NODE_CONTINUE, line));
    return b;
}

static void tco_stmt(struct AST_NODE **slot, const char *fname, char **params, int pcount, int in_loop, int *found);
static void tco_block(struct AST_NODE *b, const char *fname, char **params, int pcount, int in_loop, int *found) {
    if (!b) return;
    for (int i = 0; i < b->data.block.count; i++)
        tco_stmt(&b->data.block.stmts[i], fname, params, pcount, in_loop, found);
}
static void tco_stmt(struct AST_NODE **slot, const char *fname, char **params, int pcount, int in_loop, int *found) {
    struct AST_NODE *n = *slot;
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

static void tco_function(struct AST_NODE *f) {
    if (f->data.function.naked || f->data.function.pcount > 64) return;
    int found = 0;
    tco_block(f->data.function.body, f->data.function.name, f->data.function.params, f->data.function.pcount, 0, &found);
    if (!found) return;
    struct AST_NODE *loop = ast_new(NODE_FOR, f->line);
    loop->data.for_node.init = NULL;
    loop->data.for_node.cond = NULL;
    loop->data.for_node.inc = NULL;
    loop->data.for_node.body = f->data.function.body;
    struct AST_NODE *nb = ast_new(NODE_BLOCK, f->line);
    PUSH(nb->data.block.stmts, nb->data.block.count, nb->data.block.cap, loop);
    f->data.function.body = nb;
}

static void tco_program(struct AST_NODE *root) {
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
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
static int licm_flag[OPT_CSE_CAP];
static char *licm_tmp[OPT_CSE_CAP];
static struct { char *tmp; struct AST_NODE *val; } *licm_hoist;
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
static void licm_hoist_add(char *tmp, struct AST_NODE *val) {
    if (licm_nhoist >= licm_hcap) { licm_hcap = licm_hcap ? licm_hcap * 2 : 8; licm_hoist = realloc(licm_hoist, licm_hcap * sizeof *licm_hoist); }
    licm_hoist[licm_nhoist].tmp = tmp; licm_hoist[licm_nhoist].val = val; licm_nhoist++;
}

static void licm_collect_expr(struct AST_NODE *n) {
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

static void licm_collect_stmt(struct AST_NODE *n) {
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

static int licm_invariant(struct AST_NODE *n) {
    if (!n) return 0;
    switch (n->type) {
        case NODE_NUMBER: return 1;
        case NODE_VARIABLE: {
            const char *name = n->data.variable.name;
            if (licm_mod_has(name)) return 0;
            if (licm_has_call || licm_memwrite) return 0;
            if (out_freestanding && licm_is_global(name)) return 0;
            return 1;
        }
        case NODE_BINARY:
            if (n->data.binary.op == BIN_DIV || n->data.binary.op == BIN_MOD) return 0;
            return licm_invariant(n->data.binary.left) && licm_invariant(n->data.binary.right);
        case NODE_NOT: case NODE_BNOT: return licm_invariant(n->data.unary.value);
        default: return 0;
    }
}

static int licm_worth(struct AST_NODE *n) {
    if (n->type != NODE_BINARY) return 0;
    struct AST_NODE *l = n->data.binary.left, *r = n->data.binary.right;
    return l->type == NODE_BINARY || l->type == NODE_NOT || l->type == NODE_BNOT ||
           r->type == NODE_BINARY || r->type == NODE_NOT || r->type == NODE_BNOT;
}

static void licm_reset(void) {
    for (int i = 0; i < opt_cse_n; i++) { licm_flag[i] = 0; licm_tmp[i] = NULL; }
    opt_cse_n = 0;
    licm_nhoist = 0;
}

static void licm_count_expr(struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_NUMBER: case NODE_VARIABLE: { int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; break; }
        case NODE_BINARY:
            licm_count_expr(n->data.binary.left);
            licm_count_expr(n->data.binary.right);
            { int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; if (licm_worth(n) && licm_invariant(n)) licm_flag[v] = 1; }
            break;
        case NODE_NOT: case NODE_BNOT:
            licm_count_expr(n->data.unary.value);
            { int v = opt_cse_number(n); opt_cse_vn[OPT_NODE_IDX(n)] = v; }
            break;
        default: break;
    }
}

static void licm_count_stmt(struct AST_NODE *n) {
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

static struct AST_NODE *licm_rewrite_expr(struct AST_NODE *n) {
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
    int v = opt_cse_vn[OPT_NODE_IDX(n)];
    if (v >= 0 && licm_flag[v]) {
        if (!licm_tmp[v]) {
            char buf[32];
            sprintf(buf, "$licm%d", licm_id++);
            licm_tmp[v] = lex_intern(buf, strlen(buf));
            licm_hoist_add(licm_tmp[v], n);
        }
        return ast_variable(licm_tmp[v], n->line);
    }
    return n;
}

static void licm_rewrite_stmt(struct AST_NODE *n) {
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

static void licm_loop(struct AST_NODE *s) {
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

static void licm_block(struct AST_NODE *b);
static void licm_sub(struct AST_NODE **slot);

static void licm_block(struct AST_NODE *b) {
    if (!b) return;
    struct AST_NODE **out = NULL; int n = 0, cap = 0;
    for (int i = 0; i < b->data.block.count; i++) {
        struct AST_NODE *s = b->data.block.stmts[i];
        switch (s->type) {
            case NODE_BLOCK: licm_block(s); break;
            case NODE_IF: licm_sub(&s->data.if_node.then); licm_sub(&s->data.if_node.else_); break;
            case NODE_FUNCTION: licm_block(s->data.function.body); break;
            case NODE_SWITCH: for (int k = 0; k < s->data.switch_node.narms; k++) licm_block(s->data.switch_node.arms[k]->data.case_arm.blk); break;
            case NODE_WHILE: case NODE_FOR:
                if (s->type == NODE_WHILE) licm_sub(&s->data.while_node.body);
                else licm_sub(&s->data.for_node.body);
                licm_loop(s);
                for (int k = 0; k < licm_nhoist; k++) PUSH(out, n, cap, ast_let(licm_hoist[k].tmp, licm_hoist[k].val, s->line));
                licm_nhoist = 0;
                break;
            default: break;
        }
        PUSH(out, n, cap, s);
    }
    b->data.block.stmts = out; b->data.block.count = n; b->data.block.cap = cap;
}

static void licm_sub(struct AST_NODE **slot) {
    if (!*slot) return;
    if ((*slot)->type == NODE_BLOCK) { licm_block(*slot); return; }
    struct AST_NODE *s = *slot;
    if (s->type == NODE_WHILE || s->type == NODE_FOR) {
        if (s->type == NODE_WHILE) licm_sub(&s->data.while_node.body);
        else licm_sub(&s->data.for_node.body);
        licm_loop(s);
        if (licm_nhoist) {
            struct AST_NODE *b = ast_new(NODE_BLOCK, s->line);
            for (int k = 0; k < licm_nhoist; k++) PUSH(b->data.block.stmts, b->data.block.count, b->data.block.cap, ast_let(licm_hoist[k].tmp, licm_hoist[k].val, s->line));
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

static void licm_program(struct AST_NODE *root) {
    licm_nglob = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) licm_globals[licm_nglob++] = n->data.let.name;
    }
    licm_block(root);
}

static void opt_run(struct AST_NODE *root) {
    tco_program(root);
    opt_fold_block(root);
    opt_analyze_program(root);
    opt_propagate_program(root);
    opt_fold_block(root);
    opt_branch_block(root);
    licm_program(root);
    opt_cse_block(root);
    opt_dce_count_program(root);
    opt_dce_block(root, 1);
}

static void out_write_elf(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint64_t hdr_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    const uint64_t base = (uint64_t)out_load_base;

    Elf64_Ehdr ehdr = {
        .e_ident = { 0x7f, 'E', 'L', 'F', 2, 1, 1 },
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = base + hdr_size + emit_entry_off,
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
        .p_filesz = hdr_size + emit_len,
        .p_memsz = hdr_size + emit_len + sym_gsize,
        .p_align = 0x1000,
    };

    write(fd, &ehdr, sizeof ehdr);
    write(fd, &phdr, sizeof phdr);
    write(fd, emit_buf, emit_len);
    close(fd);
}

static const uint8_t OUT_BOOT_SEC[287] = {
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

static void out_write_bin(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }
    if (out_boot_mode) {
        static uint8_t z[65536];
        if (emit_len + sym_gsize > 65024) {
            fprintf(stderr, "error: kernel image exceeds 65024 bytes (%d)\n", emit_len + sym_gsize);
            exit(1);
        }
        int kern = emit_len + sym_gsize;
        int sectors = (kern + 511) / 512;
        uint8_t stage1[sizeof OUT_BOOT_SEC];
        memcpy(stage1, OUT_BOOT_SEC, sizeof OUT_BOOT_SEC);
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
        write(fd, z, 510 - (int)sizeof OUT_BOOT_SEC);
        write(fd, "\x55\xAA", 2);
        write(fd, emit_buf, emit_len);
        if (sym_gsize > 0) write(fd, z, sym_gsize);
        write(fd, z, sectors * 512 - kern);
        close(fd);
        printf("  boot disk: 512-byte boot sector + %d kernel sector(s) = %d bytes (%d code + %d bss)\n",
               sectors, 512 + sectors * 512, emit_len, sym_gsize);
        return;
    }
    if (out_raw_mode) {
        static uint8_t z[512];
        if (emit_len > 510) { fprintf(stderr, "error: raw boot sector exceeds 510 bytes (%d)\n", emit_len); exit(1); }
        write(fd, emit_buf, emit_len);
        if (emit_len < 510) write(fd, z, 510 - emit_len);
        write(fd, "\x55\xAA", 2);
        close(fd);
        printf("  raw boot sector: %d bytes code + %d pad + 55 AA = 512\n", emit_len, 510 - emit_len);
        return;
    }
    write(fd, emit_buf, emit_len);
    if (sym_gsize > 0) {
        static uint8_t z[4096];
        for (int left = sym_gsize; left > 0; ) {
            int n = left < (int)sizeof z ? left : (int)sizeof z;
            write(fd, z, n);
            left -= n;
        }
    }
    close(fd);
    printf("  flat binary: entry +0x%x, load 0x%llx, %d bytes (code %d + bss %d)\n",
           emit_entry_off, out_load_base, emit_len + sym_gsize, emit_len, sym_gsize);
}

static void emit_put_le(uint8_t *p, uint64_t v, int n) { memcpy(p, &v, n); }

static void out_write_pe(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0755);
    if (fd < 0) { perror("open"); exit(1); }

    const uint32_t impsz = (uint32_t)emit_pe_impsz;
    const uint32_t body = (emit_len + 15) & ~15;
    const uint32_t imp_rva = emit_pcb + body;
    const uint32_t vsize = body + impsz;
    uint8_t h[EMIT_PE_SECT_SIZE] = {0}, imp[176] = {0}, zero[16] = {0};

    h[0] = 'M'; h[1] = 'Z';
    emit_put_le(h + 0x3C, 0x40, 4);
    memcpy(h + 0x40, "PE\0\0", 4);
    emit_put_le(h + 0x44, 0x8664, 2);
    emit_put_le(h + 0x46, 1, 2);
    emit_put_le(h + 0x54, 0xF0, 2);
    emit_put_le(h + 0x56, 0x22, 2);
    emit_put_le(h + 0x58, 0x20B, 2);
    emit_put_le(h + 0x5C, emit_len, 4);
    emit_put_le(h + 0x68, emit_pcb + emit_entry_off, 4);
    emit_put_le(h + 0x6C, emit_pcb, 4);
    emit_put_le(h + 0x70, 0x400000, 8);
    emit_put_le(h + 0x78, 0x10, 4);
    emit_put_le(h + 0x7C, 0x10, 4);
    emit_put_le(h + 0x88, 6, 2);
    emit_put_le(h + 0x90, emit_pcb + vsize + ((sym_gsize + 15) & ~15), 4);
    emit_put_le(h + 0x94, emit_pcb, 4);
    emit_put_le(h + 0x9C, out_efi_mode ? 10 : 3, 2);
    emit_put_le(h + 0xA0, 0x100000, 8);
    emit_put_le(h + 0xA8, 0x1000, 8);
    emit_put_le(h + 0xB0, 0x100000, 8);
    emit_put_le(h + 0xB8, 0x1000, 8);
    emit_put_le(h + 0xC4, 16, 4);
    if (!out_efi_mode) {
        emit_put_le(h + 0xD0, imp_rva, 4);
        emit_put_le(h + 0xD4, 40, 4);
    }
    emit_put_le(h + 0x150, vsize + sym_gsize, 4);
    emit_put_le(h + 0x154, emit_pcb, 4);
    emit_put_le(h + 0x158, vsize, 4);
    emit_put_le(h + 0x15C, emit_pcb, 4);
    emit_put_le(h + 0x16C, sym_gsize ? 0xE00000E0 : 0x60000020, 4);

    if (!out_efi_mode) {
        emit_put_le(imp + 12, imp_rva + 104, 4);
        emit_put_le(imp + 16, imp_rva + 72, 4);
        memcpy(imp + 104, "kernel32.dll", 13);
        const char *FN[3] = { "GetStdHandle", "WriteFile", "ExitProcess" };
        for (int i = 0, off = 120; i < 3; i++) {
            emit_put_le(imp + 40 + i * 8, imp_rva + off, 4);
            emit_put_le(imp + 72 + i * 8, imp_rva + off, 4);
            memcpy(imp + off + 2, FN[i], strlen(FN[i]));
            off += (int)(strlen(FN[i]) + 4) & ~1;
        }
    }

    write(fd, h, emit_pcb);
    write(fd, emit_buf, emit_len);
    if (body > (uint32_t)emit_len) write(fd, zero, body - emit_len);
    if (!out_efi_mode) write(fd, imp, 176);
    close(fd);
}

enum DRV_LIMITS { DRV_MAX_IMPORT = 64 };
static char DRV_IMPORTED[DRV_MAX_IMPORT][512];
static int drv_nimported;

static int drv_import_seen(const char *p) {
    for (int i = 0; i < drv_nimported; i++)
        if (!strcmp(DRV_IMPORTED[i], p)) return 1;
    return 0;
}
static void drv_import_mark(const char *p) {
    if (drv_nimported >= DRV_MAX_IMPORT) die("too many imports", 0);
    strncpy(DRV_IMPORTED[drv_nimported], p, 511);
    DRV_IMPORTED[drv_nimported][511] = 0;
    drv_nimported++;
}
static void drv_resolve_path(const char *cur, const char *name, char *out) {
    if (name[0] == '/') { snprintf(out, 4096, "%s", name); return; }
    const char *s = strrchr(cur, '/');
    if (!s) snprintf(out, 4096, "%s", name);
    else snprintf(out, 4096, "%.*s/%s", (int)(s - cur), cur, name);
}

static struct TOKEN *lex_source(const char *path, int *out_n) {
    FILE *sf = fopen(path, "rb");
    if (!sf) { perror(path); exit(1); }
    fseek(sf, 0, SEEK_END);
    long size = ftell(sf);
    rewind(sf);
    char *src = malloc(size + 1);
    if (!src || fread(src, 1, size, sf) != (size_t)size) { fprintf(stderr, "Cannot read %s\n", path); exit(1); }
    src[size] = 0;
    fclose(sf);
    struct LEX_STATE lx = { src, 0, 1 };
    struct TOKEN *tokens = NULL;
    int tcnt = 0, tcap = 0;
    struct TOKEN tk;
    do {
        tk = lex_next_token(&lx);
        PUSH(tokens, tcnt, tcap, tk);
    } while (tk.type != TOK_EOF && tk.type != TOK_ERROR);
    if (tk.type == TOK_ERROR) { fprintf(stderr, "Lex error in %s\n", path); exit(1); }
    free(src);
    *out_n = tcnt;
    return tokens;
}

static void lex_load_file(const char *path, struct TOKEN **tokens, int *tcnt, int *tcap) {
    int n = 0;
    struct TOKEN *t = lex_source(path, &n);
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
            drv_resolve_path(path, nm, full);
            if (!drv_import_seen(full)) { drv_import_mark(full); lex_load_file(full, tokens, tcnt, tcap); }
            i += 3;
            continue;
        }
        PUSH(*tokens, *tcnt, *tcap, t[i]);
    }
}

enum IR_TYPE { IRTY_I1, IRTY_I8, IRTY_I64, IRTY_PTR, IRTY_VOID, IRTY_I32 };
enum IR_VKIND { IRVK_CONST, IRVK_REG, IRVK_GLOBAL, IRVK_FUNC, IRVK_LIT };
struct IR_VALUE { enum IR_VKIND k; long c; int id; const char *nm; };

enum IR_OP {
    IROP_BIN, IROP_ICMP, IROP_LOAD, IROP_STORE, IROP_ALLOCA, IROP_CALL, IROP_BR, IROP_CBR, IROP_RET, IROP_PRINT, IROP_ZEXT, IROP_TRUNC, IROP_GADDR,
    IROP_PTRADD, IROP_SYSCALL, IROP_COPY, IROP_PHI, IROP_DEAD, IROP_KERN
};

struct IR_INSN {
    enum IR_OP op; enum IR_TYPE ty; int sub; int dst; struct IR_VALUE a, b; int t1, t2;
    struct IR_VALUE *args; int nargs; int *ppred;
    const char *nm;
    long bytes;
    int mk;
    struct IR_INSN *next;
};

struct IR_BLOCK { int id; char nm[16]; struct IR_INSN *head, *tail; struct IR_BLOCK *next; };
struct IR_FUNC { const char *nm; int np; char **params; int preg[16]; struct IR_BLOCK *blocks, *cur; struct IR_FUNC *next; int naked; };

static struct IR_FUNC *ir_funcs;
static int ir_nreg = 1, ir_nblk = 0;
static int ir_brk = -1, ir_cont = -1;

static struct { const char *nm; enum IR_TYPE ty; long init; int has_init; struct TYPE *gast; } ir_globals[256];
static int ir_nglob;
static struct { const char *data; int len; } ir_strs[256];
static int ir_nstr;

enum IR_BINOP { IRBIN_ADD, IRBIN_SUB, IRBIN_MUL, IRBIN_SDIV, IRBIN_SREM, IRBIN_AND, IRBIN_OR, IRBIN_XOR, IRBIN_SHL, IRBIN_SAR };
enum IR_CMP { IRCMP_EQ, IRCMP_NE, IRCMP_SLT, IRCMP_SLE, IRCMP_SGT, IRCMP_SGE };

static enum IR_TYPE ir_ty(struct TYPE *t) {
    if (!t) return IRTY_I64;
    if (t->kind == 1 || t->kind == 2 || t->kind == 3) return IRTY_PTR;
    return t->sz == 1 ? IRTY_I8 : IRTY_I64;
}

static struct IR_VALUE ir_const(long c) { struct IR_VALUE v = { IRVK_CONST, c, 0, NULL }; return v; }
static struct IR_VALUE ir_reg(int id) { struct IR_VALUE v = { IRVK_REG, 0, id, NULL }; return v; }

static struct IR_BLOCK *ir_newblock(struct IR_FUNC *f, const char *hint) {
    struct IR_BLOCK *b = calloc(1, sizeof *b);
    b->id = ir_nblk++;
    sprintf(b->nm, "L%d", b->id);
    (void)hint;
    if (f->blocks) { struct IR_BLOCK *p = f->blocks; while (p->next) p = p->next; p->next = b; }
    else f->blocks = b;
    return b;
}

static struct IR_INSN *ir_emit(struct IR_FUNC *f, enum IR_OP op) {
    struct IR_INSN *in = calloc(1, sizeof *in);
    in->op = op; in->dst = -1;
    if (f->cur->tail) { f->cur->tail->next = in; f->cur->tail = in; }
    else { f->cur->head = f->cur->tail = in; }
    return in;
}

static struct IR_VALUE ir_bin(struct IR_FUNC *f, int sub, struct IR_VALUE a, struct IR_VALUE b) {
    struct IR_INSN *in = ir_emit(f, IROP_BIN); in->sub = sub; in->ty = IRTY_I64; in->dst = ir_nreg++; in->a = a; in->b = b;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_icmp(struct IR_FUNC *f, int sub, struct IR_VALUE a, struct IR_VALUE b) {
    struct IR_INSN *in = ir_emit(f, IROP_ICMP); in->sub = sub; in->ty = IRTY_I1; in->dst = ir_nreg++; in->a = a; in->b = b;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_alloca(struct IR_FUNC *f, enum IR_TYPE ty, long bytes) {
    struct IR_INSN *in = ir_emit(f, IROP_ALLOCA); in->ty = ty; in->dst = ir_nreg++; in->bytes = bytes;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_ptradd(struct IR_FUNC *f, struct IR_VALUE a, struct IR_VALUE b) {
    struct IR_INSN *in = ir_emit(f, IROP_PTRADD); in->ty = IRTY_PTR; in->dst = ir_nreg++; in->a = a; in->b = b;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_load(struct IR_FUNC *f, enum IR_TYPE ty, struct IR_VALUE p) {
    struct IR_INSN *in = ir_emit(f, IROP_LOAD); in->ty = ty; in->dst = ir_nreg++; in->a = p;
    return ir_reg(in->dst);
}
static void ir_store(struct IR_FUNC *f, enum IR_TYPE ty, struct IR_VALUE v, struct IR_VALUE p) {
    struct IR_INSN *in = ir_emit(f, IROP_STORE); in->ty = ty; in->a = v; in->b = p;
}
static struct IR_VALUE ir_zext(struct IR_FUNC *f, struct IR_VALUE a) {
    struct IR_INSN *in = ir_emit(f, IROP_ZEXT); in->ty = IRTY_I64; in->dst = ir_nreg++; in->a = a;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_trunc(struct IR_FUNC *f, struct IR_VALUE a) {
    struct IR_INSN *in = ir_emit(f, IROP_TRUNC); in->ty = IRTY_I8; in->dst = ir_nreg++; in->a = a;
    return ir_reg(in->dst);
}
static struct IR_VALUE ir_gaddr(struct IR_FUNC *f, const char *nm) {
    struct IR_INSN *in = ir_emit(f, IROP_GADDR); in->ty = IRTY_PTR; in->dst = ir_nreg++; in->nm = nm;
    return ir_reg(in->dst);
}

static int ir_terminated(struct IR_FUNC *f) {
    if (!f->cur->tail) return 0;
    enum IR_OP op = f->cur->tail->op;
    return op == IROP_RET || op == IROP_BR || op == IROP_CBR;
}

static struct { const char *nm; struct IR_VALUE val; enum IR_TYPE ty; struct TYPE *ast; } ir_sym[4096];
static int ir_symn;
static int ir_lookup(const char *nm, struct IR_VALUE *val, enum IR_TYPE *ty) {
    for (int i = ir_symn - 1; i >= 0; i--) {
        if (!strcmp(ir_sym[i].nm, nm)) { *val = ir_sym[i].val; *ty = ir_sym[i].ty; return 1; }
    }
    return 0;
}
static struct TYPE *ir_sym_ast(const char *nm) {
    for (int i = ir_symn - 1; i >= 0; i--)
        if (!strcmp(ir_sym[i].nm, nm)) return ir_sym[i].ast;
    return NULL;
}
static void ir_bind(const char *nm, struct IR_VALUE val, enum IR_TYPE ty, struct TYPE *ast) {
    ir_sym[ir_symn].nm = nm; ir_sym[ir_symn].val = val; ir_sym[ir_symn].ty = ty; ir_sym[ir_symn].ast = ast; ir_symn++;
}
static enum IR_TYPE ir_global_ty(const char *nm) {
    for (int i = 0; i < ir_nglob; i++) if (!strcmp(ir_globals[i].nm, nm)) return ir_globals[i].ty;
    return IRTY_I64;
}
static struct TYPE *ir_global_ast(const char *nm) {
    for (int i = 0; i < ir_nglob; i++) if (!strcmp(ir_globals[i].nm, nm)) return ir_globals[i].gast;
    return NULL;
}

static int ir_map_bin(enum BIN_OP op) {
    switch (op) {
        case BIN_SUB: return IRBIN_SUB;
        case BIN_MUL: return IRBIN_MUL;
        case BIN_DIV: return IRBIN_SDIV;
        case BIN_MOD: return IRBIN_SREM;
        case BIN_BAND: return IRBIN_AND;
        case BIN_BOR: return IRBIN_OR;
        case BIN_BXOR: return IRBIN_XOR;
        case BIN_SHL: return IRBIN_SHL;
        case BIN_SHR: return IRBIN_SAR;
        default: return IRBIN_ADD;
    }
}
static int ir_map_cmp(enum BIN_OP op) {
    switch (op) {
        case BIN_NE: return IRCMP_NE;
        case BIN_LT: return IRCMP_SLT;
        case BIN_LE: return IRCMP_SLE;
        case BIN_GT: return IRCMP_SGT;
        case BIN_GE: return IRCMP_SGE;
        default: return IRCMP_EQ;
    }
}

static struct IR_VALUE ir_lower_expr(struct IR_FUNC *f, struct AST_NODE *n);
static void ir_lower_stmt(struct IR_FUNC *f, struct AST_NODE *n);

static struct TYPE *ir_expr_ty(struct AST_NODE *n);

static struct TYPE *ir_var_ty(const char *nm) {
    struct TYPE *t = ir_sym_ast(nm);
    if (t) return t;
    t = ir_global_ast(nm);
    return t ? t : &TYPE_INT;
}

static struct TYPE *ir_struct_of(struct AST_NODE *b, int arrow) {
    struct TYPE *bt = ir_expr_ty(b);
    if (arrow) { if (bt->kind != 1) die("-> applied to non-pointer", b->line); bt = bt->base; }
    if (!bt || bt->kind != 3) die("member access on non-struct", b->line);
    return bt;
}

static int ir_is_char_ty(struct TYPE *t) { return t && t->kind == 0 && t->sz == 1; }
static enum IR_TYPE ir_mem_ty(struct TYPE *t) { return ir_is_char_ty(t) ? IRTY_I8 : IRTY_I64; }

static struct TYPE *ir_expr_ty(struct AST_NODE *n) {
    switch (n->type) {
        case NODE_VARIABLE: return ir_var_ty(n->data.variable.name);
        case NODE_STR:      return type_pointer(&TYPE_CHAR);
        case NODE_DEREF:  { struct TYPE *t = ir_expr_ty(n->data.unary.value); return t->kind ? t->base : &TYPE_INT; }
        case NODE_INDEX:  { struct TYPE *t = ir_expr_ty(n->data.index.base); return t->kind ? t->base : &TYPE_INT; }
        case NODE_ADDR:     return type_pointer(ir_expr_ty(n->data.unary.value));
        case NODE_MEMBER: {
            struct TYPE_FIELD *fl = type_find_field(ir_struct_of(n->data.member.base, n->data.member.arrow), n->data.member.field);
            if (!fl) die("no such field", n->line);
            return fl->ty;
        }
        default: return &TYPE_INT;
    }
}

static struct IR_VALUE ir_lower_addr(struct IR_FUNC *f, struct AST_NODE *n) {
    switch (n->type) {
        case NODE_VARIABLE: {
            struct IR_VALUE p; enum IR_TYPE ty;
            if (ir_lookup(n->data.variable.name, &p, &ty)) return p;
            if (sym_func_find(n->data.variable.name) >= 0) {
                struct IR_VALUE v;
                v.k = IRVK_FUNC; v.nm = n->data.variable.name; v.c = 0; v.id = 0;
                return v;
            }
            return ir_gaddr(f, n->data.variable.name);
        }
        case NODE_DEREF: return ir_lower_expr(f, n->data.unary.value);
        case NODE_INDEX: {
            struct TYPE *bt = ir_expr_ty(n->data.index.base);
            struct IR_VALUE base = bt->kind == 1 ? ir_lower_expr(f, n->data.index.base) : ir_lower_addr(f, n->data.index.base);
            struct IR_VALUE iv = ir_lower_expr(f, n->data.index.index);
            int es = type_size(ir_expr_ty(n));
            if (es != 1 && es != 8) iv = ir_bin(f, IRBIN_MUL, iv, ir_const(es));
            else if (es == 8) iv = ir_bin(f, IRBIN_SHL, iv, ir_const(3));
            return ir_ptradd(f, base, iv);
        }
        case NODE_MEMBER: {
            struct TYPE_FIELD *fl = type_find_field(ir_struct_of(n->data.member.base, n->data.member.arrow), n->data.member.field);
            if (!fl) die("no such field", n->line);
            struct IR_VALUE base = n->data.member.arrow ? ir_lower_expr(f, n->data.member.base) : ir_lower_addr(f, n->data.member.base);
            if (fl->off) return ir_bin(f, IRBIN_ADD, base, ir_const(fl->off));
            return base;
        }
        default: die("not addressable", n->line); return ir_const(0);
    }
}

static int ir_is_str_arg(struct AST_NODE *e) {
    struct TYPE *t = ir_expr_ty(e);
    return (t->kind == 1 || t->kind == 2) && type_is_char(t->base);
}

static struct IR_VALUE ir_lower_logic(struct IR_FUNC *f, struct AST_NODE *n) {
    int is_and = n->data.binary.op == BIN_AND;
    struct IR_VALUE tmp = ir_alloca(f, IRTY_I1, 8);
    struct IR_VALUE a = ir_lower_expr(f, n->data.binary.left);
    struct IR_VALUE ac = ir_icmp(f, IRCMP_NE, a, ir_const(0));
    struct IR_BLOCK *rhs = ir_newblock(f, "logic.rhs");
    struct IR_BLOCK *sc = ir_newblock(f, "logic.sc");
    struct IR_BLOCK *end = ir_newblock(f, "logic.end");
    struct IR_INSN *cbr = ir_emit(f, IROP_CBR); cbr->a = ac; cbr->t1 = is_and ? rhs->id : sc->id; cbr->t2 = is_and ? sc->id : rhs->id;
    f->cur = sc;
    ir_store(f, IRTY_I1, is_and ? ir_const(0) : ir_const(1), tmp);
    ir_emit(f, IROP_BR)->t1 = end->id;
    f->cur = rhs;
    struct IR_VALUE b = ir_lower_expr(f, n->data.binary.right);
    struct IR_VALUE bc = ir_icmp(f, IRCMP_NE, b, ir_const(0));
    ir_store(f, IRTY_I1, bc, tmp);
    ir_emit(f, IROP_BR)->t1 = end->id;
    f->cur = end;
    return ir_load(f, IRTY_I1, tmp);
}

static struct IR_VALUE ir_lower_expr(struct IR_FUNC *f, struct AST_NODE *n) {
    switch (n->type) {
        case NODE_NUMBER: return ir_const(n->data.number.value);
        case NODE_VARIABLE: {
            struct IR_VALUE p; enum IR_TYPE ty;
            struct TYPE *ast = ir_sym_ast(n->data.variable.name);
            if (ir_lookup(n->data.variable.name, &p, &ty)) {
                if (ast && ast->kind == 2) return p;
            } else {
                p = ir_gaddr(f, n->data.variable.name);
                ty = ir_global_ty(n->data.variable.name);
                ast = ir_global_ast(n->data.variable.name);
                if (ast && ast->kind == 2) return p;
            }
            struct IR_VALUE v = ir_load(f, ty, p);
            return ty == IRTY_I8 ? ir_zext(f, v) : v;
        }
        case NODE_STR: {
            char nm[16];
            sprintf(nm, ".str%d", ir_nstr);
            ir_strs[ir_nstr].data = (const char *)(PARSE_LITS + n->data.str.off);
            ir_strs[ir_nstr].len = n->data.str.len;
            ir_nstr++;
            struct IR_VALUE v = { IRVK_LIT, n->data.str.off, 0, lex_intern(nm, strlen(nm)) };
            return v;
        }
        case NODE_BINARY: {
            enum BIN_OP op = n->data.binary.op;
            if (op == BIN_AND || op == BIN_OR) return ir_lower_logic(f, n);
            struct IR_VALUE a = ir_lower_expr(f, n->data.binary.left);
            struct IR_VALUE b = ir_lower_expr(f, n->data.binary.right);
            if (op >= BIN_EQ && op <= BIN_GE) return ir_icmp(f, ir_map_cmp(op), a, b);
            return ir_bin(f, ir_map_bin(op), a, b);
        }
        case NODE_NOT: {
            struct IR_VALUE a = ir_lower_expr(f, n->data.unary.value);
            return ir_icmp(f, IRCMP_EQ, a, ir_const(0));
        }
        case NODE_BNOT: {
            struct IR_VALUE a = ir_lower_expr(f, n->data.unary.value);
            return ir_bin(f, IRBIN_XOR, a, ir_const(-1));
        }
        case NODE_SIZEOF: {
            struct AST_NODE *u = n->data.unary.value;
            int sz = 8;
            if (u->type == NODE_VARIABLE) sz = type_size(ir_var_ty(u->data.variable.name));
            return ir_const(sz);
        }
        case NODE_ADDR: return ir_lower_addr(f, n->data.unary.value);
        case NODE_DEREF: {
            struct IR_VALUE p = ir_lower_expr(f, n->data.unary.value);
            enum IR_TYPE lt = ir_mem_ty(ir_expr_ty(n));
            struct IR_VALUE v = ir_load(f, lt, p);
            return lt == IRTY_I8 ? ir_zext(f, v) : v;
        }
        case NODE_INDEX: {
            struct IR_VALUE p = ir_lower_addr(f, n);
            enum IR_TYPE lt = ir_mem_ty(ir_expr_ty(n));
            struct IR_VALUE v = ir_load(f, lt, p);
            return lt == IRTY_I8 ? ir_zext(f, v) : v;
        }
        case NODE_MEMBER: {
            struct TYPE *ft = ir_expr_ty(n);
            struct IR_VALUE p = ir_lower_addr(f, n);
            if (ft->kind == 2 || ft->kind == 3) return p;
            struct IR_VALUE v = ir_load(f, ir_mem_ty(ft), p);
            return ir_mem_ty(ft) == IRTY_I8 ? ir_zext(f, v) : v;
        }
        case NODE_ASSIGN: {
            struct IR_VALUE rhs = ir_lower_expr(f, n->data.assign.rhs);
            if (n->data.assign.lhs->type == NODE_VARIABLE) {
                struct IR_VALUE p; enum IR_TYPE ty;
                if (!ir_lookup(n->data.assign.lhs->data.variable.name, &p, &ty)) {
                    p = ir_gaddr(f, n->data.assign.lhs->data.variable.name);
                    ty = ir_global_ty(n->data.assign.lhs->data.variable.name);
                }
                if (n->data.assign.cop) {
                    struct IR_VALUE cur = ir_load(f, ty, p);
                    if (ty == IRTY_I8) cur = ir_zext(f, cur);
                    rhs = ir_bin(f, ir_map_bin((enum BIN_OP)(n->data.assign.cop - 1)), cur, rhs);
                }
                if (ty == IRTY_I8) rhs = ir_trunc(f, rhs);
                ir_store(f, ty, rhs, p);
                return rhs;
            }
            struct IR_VALUE p = ir_lower_addr(f, n->data.assign.lhs);
            enum IR_TYPE lt = ir_mem_ty(ir_expr_ty(n->data.assign.lhs));
            if (n->data.assign.cop) {
                struct IR_VALUE cur = ir_load(f, lt, p);
                if (lt == IRTY_I8) cur = ir_zext(f, cur);
                rhs = ir_bin(f, ir_map_bin((enum BIN_OP)(n->data.assign.cop - 1)), cur, rhs);
            }
            if (lt == IRTY_I8) rhs = ir_trunc(f, rhs);
            ir_store(f, lt, rhs, p);
            return rhs;
        }
        case NODE_CALL: {
            const char *nm = n->data.call.name;
            int na = n->data.call.acount;
            if (!strcmp(nm, "syscall") && sym_func_find("syscall") < 0) {
                if (na != 4) die("syscall(nr, a, b, c)", n->line);
                struct IR_VALUE args[4];
                for (int i = 0; i < 4; i++) args[i] = ir_lower_expr(f, n->data.call.args[i]);
                struct IR_INSN *in = ir_emit(f, IROP_SYSCALL);
                in->dst = ir_nreg++; in->ty = IRTY_I64; in->nargs = 4;
                in->args = malloc(4 * sizeof(struct IR_VALUE));
                for (int i = 0; i < 4; i++) in->args[i] = args[i];
                return ir_reg(in->dst);
            }
            if (!strcmp(nm, "addr") && sym_func_find("addr") < 0 && na == 1)
                return ir_lower_addr(f, n->data.call.args[0]);
            if (sym_func_find(nm) < 0) {
                static const struct { const char *nm; int sub, na; } KERN[] = {
                    { "asm", 0, -1 }, { "cli", 1, 0 }, { "sti", 2, 0 }, { "hlt", 3, 0 },
                    { "iretq", 4, 0 }, { "lgdt", 5, 1 }, { "lidt", 6, 1 }, { "setcr3", 7, 1 },
                    { "inb", 8, 1 }, { "inl", 9, 1 }, { "outb", 10, 2 }, { "outl", 11, 2 }
                };
                for (int k = 0; k < (int)(sizeof KERN / sizeof *KERN); k++) {
                    if (strcmp(nm, KERN[k].nm)) continue;
                    if (KERN[k].na >= 0 && na != KERN[k].na) die("intrinsic: wrong argument count", n->line);
                    struct IR_VALUE kargs[8];
                    if (KERN[k].sub != 0)
                        for (int q = 0; q < na && q < 8; q++) kargs[q] = ir_lower_expr(f, n->data.call.args[q]);
                    struct IR_INSN *kn = ir_emit(f, IROP_KERN);
                    kn->sub = KERN[k].sub;
                    kn->dst = ir_nreg++; kn->ty = IRTY_I64;
                    if (kn->sub == 0) {
                        if (na < 1) die("asm() needs at least one byte", n->line);
                        uint8_t *blob = malloc((size_t)na);
                        for (int q = 0; q < na; q++) {
                            struct AST_NODE *a = n->data.call.args[q];
                            if (a->type != NODE_NUMBER || a->data.number.value < 0 || a->data.number.value > 255)
                                die("asm() args must be byte constants", n->line);
                            blob[q] = (uint8_t)a->data.number.value;
                        }
                        kn->nm = (const char *)blob;
                        kn->bytes = na;
                    } else {
                        kn->args = na ? malloc((size_t)na * sizeof(struct IR_VALUE)) : NULL;
                        kn->nargs = na;
                        for (int q = 0; q < na && q < 8; q++) kn->args[q] = kargs[q];
                    }
                    return ir_reg(kn->dst);
                }
                if (!strcmp(nm, "ld32") && na == 1) {
                    struct IR_VALUE v = ir_lower_expr(f, n->data.call.args[0]);
                    struct IR_INSN *in = ir_emit(f, IROP_LOAD);
                    in->ty = IRTY_I32; in->dst = ir_nreg++;
                    in->a = v;
                    return ir_reg(in->dst);
                }
                if (!strcmp(nm, "st32") && na == 2) {
                    struct IR_VALUE v = ir_lower_expr(f, n->data.call.args[1]);
                    struct IR_VALUE p = ir_lower_expr(f, n->data.call.args[0]);
                    struct IR_INSN *in = ir_emit(f, IROP_STORE);
                    in->ty = IRTY_I32;
                    in->a = v; in->b = p;
                    struct IR_INSN *cp = ir_emit(f, IROP_COPY);
                    cp->ty = IRTY_I64; cp->dst = ir_nreg++; cp->a = v;
                    return ir_reg(cp->dst);
                }
                die("call to undefined function (IR backend)", n->line);
            }
            struct IR_VALUE args[64];
            for (int i = 0; i < na; i++) args[i] = ir_lower_expr(f, n->data.call.args[i]);
            struct IR_INSN *in = ir_emit(f, IROP_CALL);
            in->dst = ir_nreg++; in->ty = IRTY_I64;
            in->nm = nm;
            in->args = na ? malloc(na * sizeof(struct IR_VALUE)) : NULL;
            in->nargs = na;
            for (int i = 0; i < na; i++) in->args[i] = args[i];
            return ir_reg(in->dst);
        }
        default:
            return ir_const(0);
    }
}

static void ir_lower_print(struct IR_FUNC *f, struct AST_NODE *n) {
    for (int i = 0; i < n->data.print.ncount; i++) {
        struct AST_NODE *a = n->data.print.args[i];
        struct IR_VALUE v = ir_lower_expr(f, a);
        struct IR_INSN *in = ir_emit(f, IROP_PRINT);
        in->sub = ir_is_str_arg(a) ? 1 : 0;
        in->a = v;
    }
}

static void ir_lower_stmt(struct IR_FUNC *f, struct AST_NODE *n) {
    if (!n) return;
    switch (n->type) {
        case NODE_LET: {
            struct TYPE *ast = n->data.let.ty;
            enum IR_TYPE ty = ir_ty(ast);
            long bytes = (ast->kind == 2 || ast->kind == 3) ? type_size(ast) : 8;
            struct IR_VALUE p = ir_alloca(f, ty, bytes);
            if (n->data.let.value) {
                struct IR_VALUE v = ir_lower_expr(f, n->data.let.value);
                if (ty == IRTY_I8) v = ir_trunc(f, v);
                ir_store(f, ty, v, p);
            }
            ir_bind(n->data.let.name, p, ty, ast);
            break;
        }
        case NODE_BLOCK: {
            int sn = ir_symn;
            for (int i = 0; i < n->data.block.count; i++) ir_lower_stmt(f, n->data.block.stmts[i]);
            ir_symn = sn;
            break;
        }
        case NODE_IF: {
            struct IR_VALUE c = ir_lower_expr(f, n->data.if_node.cond);
            struct IR_BLOCK *then = ir_newblock(f, "then");
            struct IR_BLOCK *els = n->data.if_node.else_ ? ir_newblock(f, "else") : NULL;
            struct IR_BLOCK *merge = ir_newblock(f, "merge");
            struct IR_INSN *cbr = ir_emit(f, IROP_CBR); cbr->a = c; cbr->t1 = then->id; cbr->t2 = els ? els->id : merge->id;
            f->cur = then; ir_lower_stmt(f, n->data.if_node.then); if (!ir_terminated(f)) ir_emit(f, IROP_BR)->t1 = merge->id;
            if (els) { f->cur = els; ir_lower_stmt(f, n->data.if_node.else_); if (!ir_terminated(f)) ir_emit(f, IROP_BR)->t1 = merge->id; }
            f->cur = merge;
            break;
        }
        case NODE_WHILE: {
            struct IR_BLOCK *header = ir_newblock(f, "while.h");
            struct IR_BLOCK *body = ir_newblock(f, "while.b");
            struct IR_BLOCK *end = ir_newblock(f, "while.e");
            ir_emit(f, IROP_BR)->t1 = header->id;
            f->cur = header;
            struct IR_VALUE c = ir_lower_expr(f, n->data.while_node.cond);
            struct IR_INSN *cbr = ir_emit(f, IROP_CBR); cbr->a = c; cbr->t1 = body->id; cbr->t2 = end->id;
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = header->id;
            f->cur = body; ir_lower_stmt(f, n->data.while_node.body); if (!ir_terminated(f)) ir_emit(f, IROP_BR)->t1 = header->id;
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_FOR: {
            if (n->data.for_node.init) ir_lower_stmt(f, n->data.for_node.init);
            struct IR_BLOCK *header = ir_newblock(f, "for.h");
            struct IR_BLOCK *body = ir_newblock(f, "for.b");
            struct IR_BLOCK *cont = ir_newblock(f, "for.c");
            struct IR_BLOCK *end = ir_newblock(f, "for.e");
            ir_emit(f, IROP_BR)->t1 = header->id;
            f->cur = header;
            if (n->data.for_node.cond) {
                struct IR_VALUE c = ir_lower_expr(f, n->data.for_node.cond);
                struct IR_INSN *cbr = ir_emit(f, IROP_CBR); cbr->a = c; cbr->t1 = body->id; cbr->t2 = end->id;
            } else ir_emit(f, IROP_BR)->t1 = body->id;
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = cont->id;
            f->cur = body; ir_lower_stmt(f, n->data.for_node.body); if (!ir_terminated(f)) ir_emit(f, IROP_BR)->t1 = cont->id;
            f->cur = cont;
            if (n->data.for_node.inc) ir_lower_expr(f, n->data.for_node.inc);
            ir_emit(f, IROP_BR)->t1 = header->id;
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_RETURN: {
            if (n->data.return_node.value) {
                struct IR_VALUE v = ir_lower_expr(f, n->data.return_node.value);
                struct IR_INSN *in = ir_emit(f, IROP_RET); in->a = v; in->ty = IRTY_I64;
            } else {
                ir_emit(f, IROP_RET)->ty = IRTY_VOID;
            }
            break;
        }
        case NODE_PRINT: ir_lower_print(f, n); break;
        case NODE_BREAK: ir_emit(f, IROP_BR)->t1 = ir_brk; break;
        case NODE_CONTINUE: ir_emit(f, IROP_BR)->t1 = ir_cont; break;
        case NODE_SWITCH: {
            struct AST_NODE **arms = n->data.switch_node.arms;
            int na = n->data.switch_node.narms;
            struct IR_VALUE v = ir_lower_expr(f, n->data.switch_node.expr);
            struct IR_BLOCK *end = ir_newblock(f, "sw.e");
            struct IR_BLOCK *alab[64];
            if (na > 64) die("too many switch arms", n->line);
            int defidx = -1;
            for (int k = 0; k < na; k++) {
                alab[k] = ir_newblock(f, "sw.a");
                if (arms[k]->data.case_arm.is_default) defidx = k;
            }
            int sb = ir_brk, sc = ir_cont;
            ir_brk = end->id; ir_cont = end->id;
            struct IR_BLOCK *chain = ir_newblock(f, "sw.c");
            ir_emit(f, IROP_BR)->t1 = chain->id;
            for (int k = 0; k < na; k++) {
                f->cur = chain;
                if (!arms[k]->data.case_arm.is_default) {
                    struct IR_VALUE c = ir_icmp(f, IRCMP_EQ, v, ir_const(arms[k]->data.case_arm.val));
                    struct IR_BLOCK *next = ir_newblock(f, "sw.c");
                    struct IR_INSN *cbr = ir_emit(f, IROP_CBR); cbr->a = c; cbr->t1 = alab[k]->id; cbr->t2 = next->id;
                    chain = next;
                }
            }
            f->cur = chain;
            ir_emit(f, IROP_BR)->t1 = (defidx >= 0 ? alab[defidx] : end)->id;
            for (int k = 0; k < na; k++) {
                f->cur = alab[k];
                ir_lower_stmt(f, arms[k]->data.case_arm.blk);
                if (!ir_terminated(f))
                    ir_emit(f, IROP_BR)->t1 = (k + 1 < na ? alab[k + 1] : end)->id;
            }
            ir_brk = sb; ir_cont = sc;
            f->cur = end;
            break;
        }
        case NODE_EXTERN_FUNC: case NODE_EXTERN_GLOB: break;
        default: ir_lower_expr(f, n); break;
    }
}

static struct IR_FUNC *ir_newfunc(const char *nm, int np, char **params) {
    struct IR_FUNC *fn = calloc(1, sizeof *fn);
    fn->nm = nm; fn->np = np; fn->params = params;
    if (ir_funcs) { struct IR_FUNC *p = ir_funcs; while (p->next) p = p->next; p->next = fn; }
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
static const char *ir_ty_name(enum IR_TYPE ty) {
    static const char *nm[] = { "i1", "i8", "i64", "ptr", "void", "i32" };
    return nm[ty];
}
static void ir_print_v(struct IR_VALUE v) {
    if (v.k == IRVK_CONST) printf("%ld", v.c);
    else if (v.k == IRVK_REG) printf("%%v%d", v.id);
    else if (v.k == IRVK_GLOBAL) printf("@%s", v.nm);
    else if (v.k == IRVK_FUNC) printf("@%s", v.nm);
    else if (v.k == IRVK_LIT) printf("@%s", v.nm);
}
static void ir_print_blk(int id) {
    for (struct IR_FUNC *f = ir_funcs; f; f = f->next)
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
            if (b->id == id) { printf("label %%%s", b->nm); return; }
    printf("label %%L%d", id);
}

static void ir_print_fn(struct IR_FUNC *f) {
    printf("\nfunc @%s(", f->nm);
    for (int i = 0; i < f->np; i++) printf("%s%s", i ? ", " : "", f->params[i]);
    printf(") {\n");
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
        printf("%s:\n", b->nm);
        for (struct IR_INSN *in = b->head; in; in = in->next) {
                printf("  ");
                switch (in->op) {
                    case IROP_BIN: printf("%%v%d = %s i64 ", in->dst, ir_bin_name(in->sub)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case IROP_ICMP: printf("%%v%d = icmp %s i64 ", in->dst, ir_cmp_name(in->sub)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case IROP_LOAD: printf("%%v%d = load %s, ", in->dst, ir_ty_name(in->ty)); ir_print_v(in->a); break;
                    case IROP_STORE: printf("store %s ", ir_ty_name(in->ty)); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case IROP_ALLOCA: printf("%%v%d = alloca %s", in->dst, ir_ty_name(in->ty)); break;
                    case IROP_CALL: printf("%%v%d = call i64 @%s(", in->dst, in->nm); for (int k = 0; k < in->nargs; k++) { if (k) printf(", "); ir_print_v(in->args[k]); } printf(")"); break;
                    case IROP_BR: printf("br "); ir_print_blk(in->t1); break;
                    case IROP_CBR: printf("cbr i1 "); ir_print_v(in->a); printf(", "); ir_print_blk(in->t1); printf(", "); ir_print_blk(in->t2); break;
                    case IROP_RET: if (in->ty == IRTY_VOID) printf("ret void"); else { printf("ret i64 "); ir_print_v(in->a); } break;
                    case IROP_PRINT: printf("print %s ", in->sub ? "str" : "i64"); ir_print_v(in->a); break;
                    case IROP_ZEXT: printf("%%v%d = zext i8 ", in->dst); ir_print_v(in->a); printf(" to i64"); break;
                    case IROP_TRUNC: printf("%%v%d = trunc i64 ", in->dst); ir_print_v(in->a); printf(" to i8"); break;
                    case IROP_GADDR: printf("%%v%d = global.addr @%s", in->dst, in->nm); break;
                    case IROP_PTRADD: printf("%%v%d = ptradd ", in->dst); ir_print_v(in->a); printf(", "); ir_print_v(in->b); break;
                    case IROP_SYSCALL: printf("%%v%d = syscall(", in->dst); for (int k = 0; k < in->nargs; k++) { if (k) printf(", "); ir_print_v(in->args[k]); } printf(")"); break;
                    case IROP_KERN: printf("%%v%d = kern<%d>", in->dst, in->sub); break;
                    case IROP_COPY: printf("%%v%d = copy ", in->dst); ir_print_v(in->a); break;
                    case IROP_PHI:
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
    for (struct IR_FUNC *f = ir_funcs; f; f = f->next) ir_print_fn(f);
}

static void ir_lower_function(struct AST_NODE *n) {
    struct IR_FUNC *f = ir_newfunc(n->data.function.name, n->data.function.pcount, n->data.function.params);
    f->naked = n->data.function.naked;
    struct IR_BLOCK *emit_entry_off = ir_newblock(f, "entry");
    f->cur = emit_entry_off;
    ir_symn = 0;
    for (int i = 0; i < n->data.function.pcount; i++) {
        if (f->naked) continue;
        struct IR_VALUE param = ir_reg(ir_nreg++);
        struct IR_VALUE p = ir_alloca(f, IRTY_I64, 8);
        ir_store(f, IRTY_I64, param, p);
        if (i < 16) f->preg[i] = param.id;
        ir_bind(n->data.function.params[i], p, IRTY_I64, &TYPE_INT);
    }
    ir_lower_stmt(f, n->data.function.body);
    if (!ir_terminated(f)) {
        struct IR_INSN *in = ir_emit(f, IROP_RET); in->ty = IRTY_VOID;
    }
    ir_symn = 0;
}

static void ir_lower_program(struct AST_NODE *root) {
    ir_funcs = NULL; ir_nreg = 1; ir_nblk = 0; ir_nglob = 0; ir_nstr = 0;
    sym_nfunc = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_LET) {
            ir_globals[ir_nglob].nm = n->data.let.name;
            ir_globals[ir_nglob].ty = ir_ty(n->data.let.ty);
            ir_globals[ir_nglob].gast = n->data.let.ty;
            ir_globals[ir_nglob].has_init = 0;
            ir_nglob++;
        } else if (n->type == NODE_FUNCTION) {
            if (sym_nfunc >= (int)(sizeof SYM_FUNCS / sizeof *SYM_FUNCS)) die("too many functions", n->line);
            SYM_FUNCS[sym_nfunc++] = (typeof(SYM_FUNCS[0])){ n->data.function.name, 0, n->data.function.pcount };
        }
    }
    sym_func_hash_build();
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION) ir_lower_function(n);
    }
    struct IR_FUNC *emit_entry_off = ir_newfunc("entry", 0, NULL);
    struct IR_BLOCK *eb = ir_newblock(emit_entry_off, "entry");
    emit_entry_off->cur = eb;
    ir_symn = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type == NODE_FUNCTION || n->type == NODE_EXTERN_FUNC || n->type == NODE_EXTERN_GLOB) continue;
        if (n->type == NODE_LET) {
            if (!n->data.let.value) continue;
            for (int g = 0; g < ir_nglob; g++) {
                if (!strcmp(ir_globals[g].nm, n->data.let.name)) {
                    struct IR_VALUE v = ir_lower_expr(emit_entry_off, n->data.let.value);
                    if (ir_globals[g].ty == IRTY_I8) v = ir_trunc(emit_entry_off, v);
                    struct IR_VALUE p = ir_gaddr(emit_entry_off, n->data.let.name);
                    ir_store(emit_entry_off, ir_globals[g].ty, v, p);
                    break;
                }
            }
        } else {
            ir_lower_stmt(emit_entry_off, n);
        }
    }
    struct IR_INSN *ret = ir_emit(emit_entry_off, IROP_RET); ret->ty = IRTY_VOID;
    ir_symn = 0;
}

#define IR_BLOCK_MAX 1024
static struct IR_BLOCK *ir_cfg_blocks[IR_BLOCK_MAX];
static int ir_cfg_npred[IR_BLOCK_MAX], ir_cfg_nsucc[IR_BLOCK_MAX], ir_cfg_pred[IR_BLOCK_MAX][6], ir_cfg_succ[IR_BLOCK_MAX][2], ir_cfg_n;
static int ir_cfg_reach[IR_BLOCK_MAX], ir_cfg_idom[IR_BLOCK_MAX], ir_cfg_ndf[IR_BLOCK_MAX], ir_cfg_df[IR_BLOCK_MAX][16];
static int ir_cfg_children[IR_BLOCK_MAX][IR_BLOCK_MAX], ir_cfg_nchild[IR_BLOCK_MAX];
static uint64_t ir_cfg_dom[IR_BLOCK_MAX][IR_BLOCK_MAX / 64];
static int ir_id2x[65536];

static void ir_cfg(struct IR_FUNC *f) {
    ir_cfg_n = 0;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
        if (ir_cfg_n >= IR_BLOCK_MAX) die("too many blocks", 0);
        ir_id2x[b->id] = ir_cfg_n; ir_cfg_blocks[ir_cfg_n++] = b;
    }
    for (int i = 0; i < ir_cfg_n; i++) { ir_cfg_npred[i] = 0; ir_cfg_nsucc[i] = 0; }
    for (int i = 0; i < ir_cfg_n; i++) {
        struct IR_BLOCK *b = ir_cfg_blocks[i];
        if (!b->tail) continue;
        if (b->tail->op == IROP_BR) ir_cfg_succ[i][ir_cfg_nsucc[i]++] = ir_id2x[b->tail->t1];
        else if (b->tail->op == IROP_CBR) {
            ir_cfg_succ[i][ir_cfg_nsucc[i]++] = ir_id2x[b->tail->t1];
            ir_cfg_succ[i][ir_cfg_nsucc[i]++] = ir_id2x[b->tail->t2];
        }
    }
    for (int i = 0; i < ir_cfg_n; i++)
        for (int j = 0; j < ir_cfg_nsucc[i]; j++) {
            int t = ir_cfg_succ[i][j];
            if (ir_cfg_npred[t] >= 6) die("too many predecessors", 0);
            ir_cfg_pred[t][ir_cfg_npred[t]++] = i;
        }
}

static void ir_split_edges(struct IR_FUNC *f) {
    ir_cfg(f);
    struct { struct IR_INSN *in; int t; } spl[512];
    int ns = 0;
    for (int i = 0; i < ir_cfg_n; i++) {
        if (ir_cfg_nsucc[i] != 2) continue;
        for (int j = 0; j < 2; j++) {
            int t = ir_cfg_succ[i][j];
            if (ir_cfg_npred[t] > 1 && ns < 512) {
                spl[ns].in = ir_cfg_blocks[i]->tail;
                spl[ns].t = ir_cfg_blocks[t]->id;
                ns++;
            }
        }
    }
    for (int k = 0; k < ns; k++) {
        struct IR_BLOCK *m = ir_newblock(f, "split");
        f->cur = m;
        struct IR_INSN *br = ir_emit(f, IROP_BR);
        br->t1 = spl[k].t;
        if (spl[k].in->t1 == spl[k].t) spl[k].in->t1 = m->id;
        else spl[k].in->t2 = m->id;
    }
}

static void ir_mark_reach(void) {
    for (int i = 0; i < ir_cfg_n; i++) ir_cfg_reach[i] = 0;
    int stk[IR_BLOCK_MAX], sp = 0;
    if (ir_cfg_n) { stk[sp++] = 0; ir_cfg_reach[0] = 1; }
    while (sp) {
        int i = stk[--sp];
        for (int j = 0; j < ir_cfg_nsucc[i]; j++) {
            int t = ir_cfg_succ[i][j];
            if (!ir_cfg_reach[t]) { ir_cfg_reach[t] = 1; stk[sp++] = t; }
        }
    }
}

static void ir_prune(struct IR_FUNC *f) {
    ir_cfg(f);
    ir_mark_reach();
    struct IR_BLOCK **pp = &f->blocks;
    while (*pp) {
        struct IR_BLOCK *b = *pp;
        if (!ir_cfg_reach[ir_id2x[b->id]]) *pp = b->next;
        else pp = &b->next;
    }
    ir_cfg(f);
    ir_mark_reach();
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
        for (struct IR_INSN *in = b->head; in && in->op == IROP_PHI; in = in->next) {
            int w = 0;
            for (int k = 0; k < in->nargs; k++) {
                int px = ir_id2x[in->ppred[k]];
                int keep = px >= 0 && px < ir_cfg_n && ir_cfg_blocks[px] && ir_cfg_blocks[px]->id == in->ppred[k] && ir_cfg_reach[px];
                for (int j = 0; keep && j < ir_cfg_nsucc[px]; j++)
                    if (ir_cfg_succ[px][j] == ir_id2x[b->id]) { keep = 2; break; }
                if (keep == 2) { in->args[w] = in->args[k]; in->ppred[w] = in->ppred[k]; w++; }
            }
            in->nargs = w;
        }
    }
}

static void ir_dominators(void) {
    int nw = (ir_cfg_n + 63) / 64;
    for (int i = 0; i < ir_cfg_n; i++) {
        if (!ir_cfg_reach[i]) { memset(ir_cfg_dom[i], 0, sizeof(uint64_t) * nw); continue; }
        if (i == 0) { memset(ir_cfg_dom[i], 0, sizeof(uint64_t) * nw); ir_cfg_dom[i][0] = 1; }
        else for (int w = 0; w < nw; w++) ir_cfg_dom[i][w] = ~0ULL;
    }
    for (int iter = 0; iter < ir_cfg_n + 2; iter++) {
        int changed = 0;
        for (int i = 1; i < ir_cfg_n; i++) {
            if (!ir_cfg_reach[i]) continue;
            uint64_t nb[IR_BLOCK_MAX / 64];
            for (int w = 0; w < nw; w++) nb[w] = ~0ULL;
            int any = 0;
            for (int j = 0; j < ir_cfg_npred[i]; j++) {
                int p = ir_cfg_pred[i][j];
                if (!ir_cfg_reach[p]) continue;
                for (int w = 0; w < nw; w++) nb[w] &= ir_cfg_dom[p][w];
                any = 1;
            }
            if (!any) for (int w = 0; w < nw; w++) nb[w] = 0;
            nb[i / 64] |= 1ULL << (i % 64);
            for (int w = 0; w < nw; w++)
                if (nb[w] != ir_cfg_dom[i][w]) { ir_cfg_dom[i][w] = nb[w]; changed = 1; }
        }
        if (!changed) break;
    }
    for (int i = 0; i < ir_cfg_n; i++) ir_cfg_idom[i] = -1;
    ir_cfg_idom[0] = 0;
    for (int i = 1; i < ir_cfg_n; i++) {
        if (!ir_cfg_reach[i]) continue;
        for (int d = 0; d < ir_cfg_n; d++) {
            if (d == i || !ir_cfg_reach[d]) continue;
            if (!(ir_cfg_dom[i][d / 64] >> (d % 64) & 1)) continue;
            int same = 1;
            for (int w = 0; w < (ir_cfg_n + 63) / 64 && same; w++) {
                uint64_t x = ir_cfg_dom[i][w], y = ir_cfg_dom[d][w];
                if (i / 64 == w) x &= ~(1ULL << (i % 64));
                if (x != y) same = 0;
            }
            if (same) { ir_cfg_idom[i] = d; break; }
        }
    }
    for (int i = 0; i < ir_cfg_n; i++) { ir_cfg_nchild[i] = 0; ir_cfg_ndf[i] = 0; }
    for (int i = 1; i < ir_cfg_n; i++)
        if (ir_cfg_reach[i] && ir_cfg_idom[i] >= 0) ir_cfg_children[ir_cfg_idom[i]][ir_cfg_nchild[ir_cfg_idom[i]]++] = i;
    for (int i = 0; i < ir_cfg_n; i++) {
        if (!ir_cfg_reach[i] || ir_cfg_npred[i] < 2) continue;
        for (int j = 0; j < ir_cfg_npred[i]; j++) {
            int runner = ir_cfg_pred[i][j];
            while (runner != ir_cfg_idom[i]) {
                if (ir_cfg_ndf[runner] < 16) ir_cfg_df[runner][ir_cfg_ndf[runner]++] = i;
                if (runner == 0) break;
                runner = ir_cfg_idom[runner];
            }
        }
    }
}

static void ir_unlink_dead(struct IR_FUNC *f) {
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
        struct IR_INSN *prev = NULL, *in = b->head;
        while (in) {
            struct IR_INSN *nx = in->next;
            if (in->op == IROP_DEAD) {
                if (prev) prev->next = nx; else b->head = nx;
                if (b->tail == in) b->tail = prev;
            } else prev = in;
            in = nx;
        }
    }
}

static void ir_insert_before_tail(struct IR_BLOCK *b, struct IR_INSN *in) {
    if (!b->head) { b->head = b->tail = in; return; }
    if (b->head == b->tail) { in->next = b->tail; b->head = in; return; }
    struct IR_INSN *p = b->head;
    while (p->next != b->tail) p = p->next;
    in->next = b->tail; p->next = in;
}

static struct IR_VALUE ir_dmap_val[65536];
static unsigned char ir_dmap_ok[65536];

static struct IR_VALUE ir_rd(struct IR_VALUE v) {
    while (v.k == IRVK_REG && ir_dmap_ok[v.id]) v = ir_dmap_val[v.id];
    return v;
}

static void ir_rewrite_ops(struct IR_INSN *in) {
    in->a = ir_rd(in->a);
    in->b = ir_rd(in->b);
    for (int k = 0; k < in->nargs; k++) in->args[k] = ir_rd(in->args[k]);
}

static void ir_mem2reg(struct IR_FUNC *f) {
    ir_cfg(f);
    ir_dominators();
    struct IR_INSN *allocas[512];
    int na = 0;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next)
            if (in->op == IROP_ALLOCA) {
                if (na >= 512) die("too many allocas", 0);
                allocas[na++] = in;
            }
    int amap[65536];
    for (int i = 0; i < 65536; i++) amap[i] = -1;
    for (int i = 0; i < na; i++) amap[allocas[i]->dst] = i;

    static struct IR_VALUE stk[512][512];
    static int sp[512], cap[512];
    static unsigned char promoted[512];
    for (int i = 0; i < na; i++) { sp[i] = 0; cap[i] = 8; promoted[i] = 0; }

    for (int ai = 0; ai < na; ai++) {
        struct IR_INSN *A = allocas[ai];
        int ok = 1;
        for (struct IR_BLOCK *b = f->blocks; b && ok; b = b->next)
            for (struct IR_INSN *in = b->head; in && ok; in = in->next) {
                if (in == A) continue;
                int ua = in->a.k == IRVK_REG && in->a.id == A->dst;
                int ub = in->b.k == IRVK_REG && in->b.id == A->dst;
                if (in->op == IROP_LOAD && ua) continue;
                if (in->op == IROP_STORE && ub) continue;
                if (ua || ub) ok = 0;
                for (int k = 0; k < in->nargs; k++)
                    if (in->args[k].k == IRVK_REG && in->args[k].id == A->dst) ok = 0;
            }
        if (!ok) continue;
        promoted[ai] = 1;
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
            for (struct IR_INSN *in = b->head; in; in = in->next)
                if (in->op == IROP_STORE && in->b.k == IRVK_REG && in->b.id == A->dst) cap[ai]++;
        unsigned char hasphi[IR_BLOCK_MAX];
        memset(hasphi, 0, sizeof hasphi);
        unsigned char inwf[IR_BLOCK_MAX];
        memset(inwf, 0, sizeof inwf);
        int wlist[IR_BLOCK_MAX], wsp = 0;
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
            for (struct IR_INSN *in = b->head; in; in = in->next)
                if (in->op == IROP_STORE && in->b.k == IRVK_REG && in->b.id == A->dst) {
                    int bi = ir_id2x[b->id];
                    if (!inwf[bi]) { inwf[bi] = 1; wlist[wsp++] = bi; }
                }
        while (wsp) {
            int x = wlist[--wsp];
            for (int j = 0; j < ir_cfg_ndf[x]; j++) {
                int y = ir_cfg_df[x][j];
                if (hasphi[y]) continue;
                hasphi[y] = 1;
                struct IR_INSN *phi = calloc(1, sizeof *phi);
                phi->op = IROP_PHI; phi->ty = A->ty;
                phi->dst = ir_nreg++;
                phi->b = ir_reg(A->dst);
                phi->nargs = ir_cfg_npred[y];
                phi->args = malloc(sizeof(struct IR_VALUE) * ir_cfg_npred[y]);
                phi->ppred = malloc(sizeof(int) * ir_cfg_npred[y]);
                for (int k = 0; k < ir_cfg_npred[y]; k++) { phi->args[k] = ir_const(0); phi->ppred[k] = ir_cfg_blocks[ir_cfg_pred[y][k]]->id; }
                struct IR_BLOCK *yb = ir_cfg_blocks[y];
                phi->next = yb->head;
                yb->head = phi;
                if (!yb->tail) yb->tail = phi;
                if (!inwf[y]) { inwf[y] = 1; wlist[wsp++] = y; }
            }
        }
    }

    for (int i = 0; i < 65536; i++) ir_dmap_ok[i] = 0;

    int npr = 0, pslot[512];
    for (int ai = 0; ai < na; ai++) pslot[ai] = promoted[ai] ? npr++ : -1;
    int *pidx = npr ? malloc(sizeof(int) * (size_t)npr * ((size_t)ir_cfg_n + 1)) : NULL;

    void rename(int bi, int depth) {
        int *my = pidx + (size_t)depth * npr;
        for (int ai = 0; ai < na; ai++) if (pslot[ai] >= 0) my[pslot[ai]] = sp[ai];
        struct IR_BLOCK *b = ir_cfg_blocks[bi];
        for (struct IR_INSN *in = b->head; in && in->op == IROP_PHI; in = in->next) {
            int ai = amap[in->b.id];
            if (ai >= 0 && promoted[ai]) {
                if (sp[ai] >= cap[ai]) die("alloca stack overflow", 0);
                stk[ai][sp[ai]++] = ir_reg(in->dst);
            }
        }
        for (struct IR_INSN *in = b->head; in; in = in->next) {
            if (in->op == IROP_STORE && in->b.k == IRVK_REG && amap[in->b.id] >= 0 && promoted[amap[in->b.id]]) {
                int ai = amap[in->b.id];
                if (sp[ai] >= cap[ai]) die("alloca stack overflow", 0);
                stk[ai][sp[ai]++] = ir_rd(in->a);
                in->op = IROP_DEAD;
                continue;
            }
            if (in->op == IROP_LOAD && in->a.k == IRVK_REG && amap[in->a.id] >= 0 && promoted[amap[in->a.id]]) {
                int ai = amap[in->a.id];
                ir_dmap_val[in->dst] = sp[ai] ? stk[ai][sp[ai] - 1] : ir_const(0);
                ir_dmap_ok[in->dst] = 1;
                in->op = IROP_DEAD;
                continue;
            }
            ir_rewrite_ops(in);
        }
        for (int j = 0; j < ir_cfg_nsucc[bi]; j++) {
            int s = ir_cfg_succ[bi][j];
            struct IR_BLOCK *sb = ir_cfg_blocks[s];
            for (struct IR_INSN *in = sb->head; in && in->op == IROP_PHI; in = in->next) {
                int ai = amap[in->b.id];
                if (ai < 0 || !promoted[ai]) continue;
                for (int k = 0; k < in->nargs; k++)
                    if (in->ppred[k] == b->id) {
                        in->args[k] = sp[ai] ? stk[ai][sp[ai] - 1] : ir_const(0);
                        break;
                    }
            }
        }
        for (int c = 0; c < ir_cfg_nchild[bi]; c++) rename(ir_cfg_children[bi][c], depth + 1);
        for (int ai = 0; ai < na; ai++) if (pslot[ai] >= 0) sp[ai] = my[pslot[ai]];
    }
    if (ir_cfg_n) rename(0, 0);
    free(pidx);
    ir_unlink_dead(f);
    ir_cfg(f);
}

static void ir_ssa_apply_reps(struct IR_FUNC *f) {
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next)
            ir_rewrite_ops(in);
}

static void ir_ssa_fold(struct IR_FUNC *f) {
    for (int iter = 0; iter < 16; iter++) {
        int changed = 0;
        for (int i = 0; i < 65536; i++) ir_dmap_ok[i] = 0;
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
            for (struct IR_INSN *in = b->head; in; in = in->next) {
                if (in->op == IROP_BIN && in->a.k == IRVK_CONST && in->b.k == IRVK_CONST) {
                    long x = in->a.c, y = in->b.c, r = 0;
                    int fold = 1;
                    switch (in->sub) {
                        case IRBIN_ADD: r = x + y; break;
                        case IRBIN_SUB: r = x - y; break;
                        case IRBIN_MUL: r = x * y; break;
                        case IRBIN_SDIV: if (!y) fold = 0; else r = x / y; break;
                        case IRBIN_SREM: if (!y) fold = 0; else r = x % y; break;
                        case IRBIN_AND: r = x & y; break;
                        case IRBIN_OR: r = x | y; break;
                        case IRBIN_XOR: r = x ^ y; break;
                        case IRBIN_SHL: r = x << (y & 63); break;
                        case IRBIN_SAR: r = x >> (y & 63); break;
                    }
                    if (fold) { ir_dmap_val[in->dst] = ir_const(r); ir_dmap_ok[in->dst] = 1; in->op = IROP_DEAD; changed = 1; continue; }
                }
                if (in->op == IROP_ICMP && in->a.k == IRVK_CONST && in->b.k == IRVK_CONST) {
                    long x = in->a.c, y = in->b.c, r = 0;
                    switch (in->sub) {
                        case IRCMP_EQ: r = x == y; break;
                        case IRCMP_NE: r = x != y; break;
                        case IRCMP_SLT: r = x < y; break;
                        case IRCMP_SLE: r = x <= y; break;
                        case IRCMP_SGT: r = x > y; break;
                        case IRCMP_SGE: r = x >= y; break;
                    }
                    ir_dmap_val[in->dst] = ir_const(r); ir_dmap_ok[in->dst] = 1;
                    in->op = IROP_DEAD; changed = 1; continue;
                }
                if ((in->op == IROP_ZEXT || in->op == IROP_TRUNC) && in->a.k == IRVK_CONST) {
                    ir_dmap_val[in->dst] = ir_const(in->a.c & 0xFF); ir_dmap_ok[in->dst] = 1;
                    in->op = IROP_DEAD; changed = 1; continue;
                }
                if (in->op == IROP_CBR && in->a.k == IRVK_CONST) {
                    in->op = IROP_BR;
                    if (!in->a.c) in->t1 = in->t2;
                    changed = 1; continue;
                }
                if (in->op == IROP_PHI) {
                    struct IR_VALUE same = ir_const(0); int found = 0, allsame = 1;
                    for (int k = 0; k < in->nargs; k++) {
                        struct IR_VALUE v = in->args[k];
                        if (v.k == IRVK_REG && v.id == in->dst) continue;
                        if (!found) { same = v; found = 1; }
                        else if (v.k != same.k || v.c != same.c || v.id != same.id) allsame = 0;
                    }
                    if (found && allsame) {
                        ir_dmap_val[in->dst] = same; ir_dmap_ok[in->dst] = 1;
                        in->op = IROP_DEAD; changed = 1;
                    }
                    continue;
                }
            }
        }
        if (!changed) break;
        ir_ssa_apply_reps(f);
        ir_unlink_dead(f);
        ir_prune(f);
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
            for (struct IR_INSN *in = b->head; in; in = in->next)
                if (in->op == IROP_PHI && in->nargs == 0) in->op = IROP_DEAD;
        ir_unlink_dead(f);
    }
}

static void ir_ssa_gvn(struct IR_FUNC *f) {
    static struct { int op, sub, ty; long ka, kb, va, vb; int dst; int depth; } tbl[8192];
    int nt = 0;
    struct { int reg; struct IR_VALUE to; } reps[8192];
    int nr = 0;
    ir_cfg(f);
    ir_dominators();
    int comm[11] = { 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0 };

    void enter(int bi, int depth) {
        for (struct IR_INSN *in = ir_cfg_blocks[bi]->head; in; in = in->next) {
            if (in->op != IROP_BIN && in->op != IROP_ICMP && in->op != IROP_ZEXT && in->op != IROP_TRUNC && in->op != IROP_PTRADD && in->op != IROP_GADDR) continue;
            long ka, kb;
            ka = in->a.k == IRVK_CONST ? (0x4000000000L + in->a.c) : (0x8000000000L + in->a.id);
            kb = in->b.k == IRVK_CONST ? (0x4000000000L + in->b.c) : (0x8000000000L + in->b.id);
            if (in->a.k == IRVK_LIT) ka = 0xC000000000L + in->a.c;
            if (in->b.k == IRVK_LIT) kb = 0xC000000000L + in->b.c;
            if (in->op == IROP_GADDR) { ka = 0xD000000000L; kb = (long)(size_t)in->nm; }
            if (in->op != IROP_GADDR && comm[in->op == IROP_BIN ? in->sub : 10] && ka > kb) { long t = ka; ka = kb; kb = t; }
            int hit = -1;
            for (int i = nt - 1; i >= 0; i--) {
                if (tbl[i].op == in->op && tbl[i].sub == in->sub && tbl[i].ty == in->ty && tbl[i].ka == ka && tbl[i].kb == kb) { hit = i; break; }
            }
            if (hit >= 0) {
                if (nr < 8192) { reps[nr].reg = in->dst; reps[nr].to = ir_reg(tbl[hit].dst); nr++; }
                in->op = IROP_DEAD;
                continue;
            }
            if (nt < 8192) {
                tbl[nt].op = in->op; tbl[nt].sub = in->sub; tbl[nt].ty = in->ty;
                tbl[nt].ka = ka; tbl[nt].kb = kb; tbl[nt].dst = in->dst; tbl[nt].depth = depth;
                nt++;
            }
        }
        for (int c = 0; c < ir_cfg_nchild[bi]; c++) enter(ir_cfg_children[bi][c], depth + 1);
        while (nt > 0 && tbl[nt - 1].depth >= depth) nt--;
    }
    for (int i = 0; i < 65536; i++) ir_dmap_ok[i] = 0;
    if (ir_cfg_n) enter(0, 0);
    for (int i = 0; i < nr; i++) { ir_dmap_val[reps[i].reg] = reps[i].to; ir_dmap_ok[reps[i].reg] = 1; }
    ir_ssa_apply_reps(f);
    ir_unlink_dead(f);
}

static void ir_ssa_dce(struct IR_FUNC *f) {
    static struct IR_INSN *imap[65536];
    for (int i = 0; i < 65536; i++) imap[i] = NULL;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next)
            if (in->dst >= 0 && in->dst < 65536) imap[in->dst] = in;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next) in->mk = 0;
    static struct IR_INSN *wl[262144];
    int wsp = 0;
    #define IRMARK(x) do { struct IR_INSN *_i = (x); if (_i && !_i->mk) { _i->mk = 1; wl[wsp++] = _i; } } while (0)
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next)
            if (in->op == IROP_STORE || in->op == IROP_CALL || in->op == IROP_PRINT || in->op == IROP_SYSCALL ||
                in->op == IROP_RET || in->op == IROP_BR || in->op == IROP_CBR || in->op == IROP_ALLOCA || in->op == IROP_KERN)
                IRMARK(in);
    while (wsp) {
        struct IR_INSN *in = wl[--wsp];
        if (in->a.k == IRVK_REG && imap[in->a.id]) IRMARK(imap[in->a.id]);
        if (in->b.k == IRVK_REG && imap[in->b.id]) IRMARK(imap[in->b.id]);
        for (int k = 0; k < in->nargs; k++)
            if (in->args[k].k == IRVK_REG && imap[in->args[k].id]) IRMARK(imap[in->args[k].id]);
    }
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next)
            if (!in->mk && in->op != IROP_STORE && in->op != IROP_CALL && in->op != IROP_PRINT && in->op != IROP_SYSCALL &&
                in->op != IROP_RET && in->op != IROP_BR && in->op != IROP_CBR && in->op != IROP_ALLOCA && in->op != IROP_KERN)
                in->op = IROP_DEAD;
    ir_unlink_dead(f);
}

static void ir_out_of_ssa(struct IR_FUNC *f) {
    int any = 1;
    while (any) {
        any = 0;
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
            if (!b->head || b->head->op != IROP_PHI) continue;
            any = 1;
            struct IR_INSN *phis[512];
            int np = 0;
            for (struct IR_INSN *in = b->head; in && in->op == IROP_PHI; in = in->next)
                if (np < 512) phis[np++] = in;
            for (int k = 0; k < np; k++) phis[k]->mk = ir_nreg++;
            for (int pass = 0; pass < 2; pass++) {
                for (int k = 0; k < np; k++) {
                    struct IR_INSN *phi = phis[k];
                    for (int e = 0; e < phi->nargs; e++) {
                        struct IR_BLOCK *pb = NULL;
                        for (struct IR_BLOCK *bb = f->blocks; bb; bb = bb->next)
                            if (bb->id == phi->ppred[e]) { pb = bb; break; }
                        if (!pb) continue;
                        struct IR_INSN *cp = calloc(1, sizeof *cp);
                        cp->op = IROP_COPY; cp->dst = pass ? phi->dst : (int)phis[k]->mk;
                        cp->ty = phi->ty;
                        cp->a = pass ? ir_reg((int)phis[k]->mk) : phi->args[e];
                        ir_insert_before_tail(pb, cp);
                    }
                }
            }
            for (int k = 0; k < np; k++) phis[k]->op = IROP_DEAD;
            break;
        }
    }
    ir_unlink_dead(f);
}

static void ir_opt_function(struct IR_FUNC *f) {
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

static void ir_pipeline(struct AST_NODE *root) {
    ir_lower_program(root);
    for (struct IR_FUNC *f = ir_funcs; f; f = f->next) ir_opt_function(f);
    for (struct IR_FUNC *f = ir_funcs; f; f = f->next) ir_out_of_ssa(f);
}

#define IR_POOL_N 5
static const int IR_POOL[IR_POOL_N] = { 3, 12, 13, 14, 15 };

struct IR_ALLOC {
    int  *reg;
    long *slot;
    long *region;
    int   nreg, nsaved;
    int   saved[IR_POOL_N];
    long  framesz;
};

struct IR_LIVE { int id, start, end, r; };

static int ir_live_cmp(const void *x, const void *y) {
    const struct IR_LIVE *a = x, *b = y;
    if (a->start != b->start) return a->start < b->start ? -1 : 1;
    if (a->end != b->end) return a->end < b->end ? -1 : 1;
    return a->id - b->id;
}

static void ircg_alloc_func(struct IR_FUNC *f, struct IR_ALLOC *al) {
    int maxr = 1;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
        for (struct IR_INSN *in = b->head; in; in = in->next) {
            if (in->dst > maxr) maxr = in->dst;
            if (in->a.k == IRVK_REG && in->a.id > maxr) maxr = in->a.id;
            if (in->b.k == IRVK_REG && in->b.id > maxr) maxr = in->b.id;
            for (int k = 0; k < in->nargs; k++)
                if (in->args[k].k == IRVK_REG && in->args[k].id > maxr) maxr = in->args[k].id;
        }
    for (int i = 0; i < f->np && i < 16; i++)
        if (f->preg[i] > maxr) maxr = f->preg[i];
    int n = maxr + 2;
    al->nreg = n;
    al->nsaved = 0;
    al->framesz = 0;
    al->reg   = malloc((size_t)n * sizeof *al->reg);
    al->slot  = calloc((size_t)n, sizeof *al->slot);
    al->region = calloc((size_t)n, sizeof *al->region);
    for (int i = 0; i < n; i++) al->reg[i] = -1;

    struct IR_BLOCK *bs[IR_BLOCK_MAX];
    int nb = 0;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) {
        if (nb >= IR_BLOCK_MAX) die("IR backend supports at most 1024 blocks", 0);
        bs[nb++] = b;
    }

    int *dn = malloc((size_t)n * sizeof(int));
    for (int i = 0; i < n; i++) dn[i] = -1;
    int nd = 0;
    for (int bi = 0; bi < nb; bi++)
        for (struct IR_INSN *in = bs[bi]->head; in; in = in->next) {
            if (in->dst > 0 && dn[in->dst] < 0) dn[in->dst] = nd++;
            if (in->a.k == IRVK_REG && in->a.id > 0 && dn[in->a.id] < 0) dn[in->a.id] = nd++;
            if (in->b.k == IRVK_REG && in->b.id > 0 && dn[in->b.id] < 0) dn[in->b.id] = nd++;
            for (int k = 0; k < in->nargs; k++)
                if (in->args[k].k == IRVK_REG && in->args[k].id > 0 && dn[in->args[k].id] < 0) dn[in->args[k].id] = nd++;
        }
    for (int i = 0; i < f->np && i < 16; i++)
        if (f->preg[i] > 0 && dn[f->preg[i]] < 0) dn[f->preg[i]] = nd++;
    int *dv = malloc((size_t)(nd ? nd : 1) * sizeof(int));
    for (int i = 0; i < n; i++) if (dn[i] >= 0) dv[dn[i]] = i;

    static int succ[IR_BLOCK_MAX][2], nsucc[IR_BLOCK_MAX];
    for (int bi = 0; bi < nb; bi++) {
        nsucc[bi] = 0;
        struct IR_INSN *t = bs[bi]->tail;
        if (!t) continue;
        for (int tgt = 0; tgt < ((t->op == IROP_CBR) ? 2 : 1); tgt++) {
            if (t->op != IROP_BR && t->op != IROP_CBR) break;
            int want = tgt ? t->t2 : t->t1;
            for (int j = 0; j < nb; j++)
                if (bs[j]->id == want && nsucc[bi] < 2) { succ[bi][nsucc[bi]++] = j; break; }
        }
    }

    int W = (nd + 63) / 64;
    if (W < 1) W = 1;
    size_t bw = (size_t)W * sizeof(uint64_t);
    uint64_t *bset_use = calloc((size_t)(nb ? nb : 1), bw);
    uint64_t *bset_def = calloc((size_t)(nb ? nb : 1), bw);
    uint64_t *bset_in  = calloc((size_t)(nb ? nb : 1), bw);
    uint64_t *bset_out = calloc((size_t)(nb ? nb : 1), bw);
    int *blast = malloc((size_t)(nb ? nb : 1) * sizeof(int));
    int *bfirst = malloc((size_t)(nb ? nb : 1) * sizeof(int));

    struct IR_LIVE *lv = malloc((size_t)n * sizeof *lv);
    for (int i = 0; i < n; i++) { lv[i].id = i; lv[i].start = 0x7FFFFFFF; lv[i].end = -1; lv[i].r = -1; }

    int idx = 0;
    for (int bi = 0; bi < nb; bi++) {
        bfirst[bi] = idx;
        for (struct IR_INSN *in = bs[bi]->head; in; in = in->next, idx++) {
            uint64_t *us = bset_use + (size_t)bi * W, *df = bset_def + (size_t)bi * W;
#define IR_TOUCH(idv) do { int _v = (idv); if (_v > 0) { if (idx < lv[_v].start) lv[_v].start = idx; if (idx > lv[_v].end) lv[_v].end = idx; } } while (0)
#define IR_BIT(set, idv) do { int _d = dn[(idv)]; if (_d >= 0) (set)[_d / 64] |= 1ULL << (_d % 64); } while (0)
            if (in->dst > 0) { IR_TOUCH(in->dst); IR_BIT(df, in->dst); }
            if (in->a.k == IRVK_REG) { IR_TOUCH(in->a.id); IR_BIT(us, in->a.id); }
            if (in->b.k == IRVK_REG) { IR_TOUCH(in->b.id); IR_BIT(us, in->b.id); }
            for (int k = 0; k < in->nargs; k++)
                if (in->args[k].k == IRVK_REG) { IR_TOUCH(in->args[k].id); IR_BIT(us, in->args[k].id); }
#undef IR_TOUCH
#undef IR_BIT
        }
        blast[bi] = idx - 1;
    }

    for (int it = 0; it <= nb; it++) {
        int changed = 0;
        for (int bi = nb - 1; bi >= 0; bi--) {
            uint64_t *o = bset_out + (size_t)bi * W, *ni = bset_in + (size_t)bi * W;
            for (int j = 0; j < nsucc[bi]; j++) {
                uint64_t *s = bset_in + (size_t)succ[bi][j] * W;
                for (int w = 0; w < W; w++) if (s[w] & ~o[w]) { o[w] |= s[w]; changed = 1; }
            }
            for (int w = 0; w < W; w++) {
                uint64_t nv = bset_use[(size_t)bi * W + w] | (o[w] & ~bset_def[(size_t)bi * W + w]);
                if (nv != ni[w]) { ni[w] = nv; changed = 1; }
            }
        }
        if (!changed) break;
    }

    for (int bi = 0; bi < nb; bi++)
        for (int w = 0; w < W; w++) {
            uint64_t mo = bset_out[(size_t)bi * W + w];
            while (mo) {
                int bit = __builtin_ctzll(mo);
                mo &= mo - 1;
                int v = dv[w * 64 + bit];
                if (blast[bi] > lv[v].end) lv[v].end = blast[bi];
            }
            uint64_t mi = bset_in[(size_t)bi * W + w];
            while (mi) {
                int bit = __builtin_ctzll(mi);
                mi &= mi - 1;
                int v = dv[w * 64 + bit];
                if (bfirst[bi] < lv[v].start) lv[v].start = bfirst[bi];
            }
        }

    for (int i = 0; i < f->np && i < 16; i++)
        if (f->preg[i] > 0) {
            lv[f->preg[i]].start = -1;
            if (lv[f->preg[i]].end < 0) lv[f->preg[i]].end = 0;
        }

    int cnt = 0;
    for (int i = 0; i < n; i++) if (lv[i].end >= 0) lv[cnt++] = lv[i];
    qsort(lv, (size_t)cnt, sizeof *lv, ir_live_cmp);

    int active[IR_POOL_N], nact = 0;
    for (int i = 0; i < cnt; i++) {
        for (int a = 0; a < nact; ) {
            if (lv[active[a]].end < lv[i].start) active[a] = active[--nact];
            else a++;
        }
        if (nact < IR_POOL_N) {
            int mask = 0;
            for (int a = 0; a < nact; a++) mask |= 1 << lv[active[a]].r;
            int k = 0;
            while (mask & (1 << k)) k++;
            lv[i].r = k;
            active[nact++] = i;
        } else {
            int w = 0;
            for (int a = 1; a < nact; a++)
                if (lv[active[a]].end > lv[active[w]].end) w = a;
            if (lv[active[w]].end > lv[i].end) {
                lv[i].r = lv[active[w]].r;
                lv[active[w]].r = -1;
                active[w] = i;
            }
        }
    }

    int used = 0;
    for (int i = 0; i < cnt; i++) {
        if (lv[i].r < 0) continue;
        al->reg[lv[i].id] = IR_POOL[lv[i].r];
        used |= 1 << lv[i].r;
    }
    for (int k = 0; k < IR_POOL_N; k++)
        if (used & (1 << k)) al->saved[al->nsaved++] = IR_POOL[k];

    char *seen = calloc((size_t)n, 1);
    for (int i = 0; i < cnt; i++) seen[lv[i].id] = 1;

    long fr = 8L * al->nsaved;
    for (int bi = 0; bi < nb; bi++)
        for (struct IR_INSN *in = bs[bi]->head; in; in = in->next)
            if (in->op == IROP_ALLOCA && in->dst >= 0 && !al->region[in->dst]) {
                fr = (fr + 7) & ~7L;
                fr += in->bytes ? in->bytes : 8;
                al->region[in->dst] = -fr;
            }
    for (int i = 0; i < n; i++)
        if (seen[i] && al->reg[i] < 0) { fr += 8; al->slot[i] = -fr; }
    al->framesz = ((fr + 15) & ~15L) - 8L * al->nsaved;

    free(seen);
    free(lv);
    free(bset_use); free(bset_def); free(bset_in); free(bset_out);
    free(blast); free(bfirst); free(dv); free(dn);
}


static void ircg_free_alloc(struct IR_ALLOC *al) {
    free(al->reg); free(al->slot); free(al->region);
    al->reg = NULL; al->slot = NULL; al->region = NULL;
}

static void ircg_push(int r) {
    if (r >= 8) EMIT(0x41, (uint8_t)(0x50 | (r & 7)));
    else EMIT((uint8_t)(0x50 | r));
}

static void ircg_pop(int r) {
    if (r >= 8) EMIT(0x41, (uint8_t)(0x58 | (r & 7)));
    else EMIT((uint8_t)(0x58 | r));
}

static uint8_t ircg_rex_w(int rbit, int bbit) {
    return (uint8_t)(0x48 | (((rbit >> 3) & 1) << 2) | ((bbit >> 3) & 1));
}

static void ircg_mov_rr(int dst, int src) {
    if (dst == src) return;
    EMIT(ircg_rex_w(src, dst), 0x89, (uint8_t)(0xC0 | ((src & 7) << 3) | (dst & 7)));
}

static void ircg_mov_rm(int dst, long off) {
    EMIT((uint8_t)(0x48 | (((dst >> 3) & 1) << 2)), 0x8B);
    x64_rbp_disp(dst & 7, (int)off);
}

static void ircg_mov_mr(long off, int src) {
    EMIT((uint8_t)(0x48 | (((src >> 3) & 1) << 2)), 0x89);
    x64_rbp_disp(src & 7, (int)off);
}

static void ircg_lea_rbp(int dst, long off) {
    EMIT((uint8_t)(0x48 | (((dst >> 3) & 1) << 2)), 0x8D);
    x64_rbp_disp(dst & 7, (int)off);
}

static void ircg_lea_rip(int dst, int lab, int kind) {
    EMIT((uint8_t)(0x48 | (((dst >> 3) & 1) << 2)), 0x8D, (uint8_t)(0x05 | ((dst & 7) << 3)));
    emit_patch(kind, lab);
}

static void ircg_mov_ri(int dst, long long v) {
    if (v >= -2147483648LL && v <= 2147483647LL) {
        EMIT((uint8_t)(0x48 | ((dst >> 3) & 1)), 0xC7, (uint8_t)(0xC0 | (dst & 7)));
        emit_imm(v, 4);
    } else {
        EMIT((uint8_t)(0x48 | ((dst >> 3) & 1)), (uint8_t)(0xB8 | (dst & 7)));
        emit_imm(v, 8);
    }
}

static void ircg_load_to(int r, struct IR_VALUE v, struct IR_ALLOC *al) {
    if (v.k == IRVK_CONST) { ircg_mov_ri(r, v.c); return; }
    if (v.k == IRVK_LIT) { ircg_lea_rip(r, (int)v.c, 1); return; }
    if (v.k == IRVK_FUNC) {
        int fi = sym_func_find(v.nm);
        if (fi < 0) die("addr: unknown function", 0);
        ircg_lea_rip(r, SYM_FUNCS[fi].lab, 0);
        return;
    }
    if (v.id >= 0 && v.id < al->nreg && al->reg[v.id] >= 0) { ircg_mov_rr(r, al->reg[v.id]); return; }
    ircg_mov_rm(r, al->slot[v.id]);
}

static void ircg_store_from(int r, int dst, struct IR_ALLOC *al) {
    if (dst < 0 || dst >= al->nreg) return;
    if (al->reg[dst] >= 0) ircg_mov_rr(al->reg[dst], r);
    else ircg_mov_mr(al->slot[dst], r);
}

static int ircg_val_reg(struct IR_VALUE v, struct IR_ALLOC *al) {
    if (v.k != IRVK_REG) return -1;
    return al->reg[v.id];
}

static const int ircg_arith_rr[6]  = { 0x01, 0x29, 0x21, 0x09, 0x31, 0x39 };
static const int ircg_arith_rm[6]  = { 0x03, 0x2B, 0x23, 0x0B, 0x33, 0x3B };
static const int ircg_arith_dig[6] = { 0, 5, 4, 1, 6, 7 };

static void ircg_arith(int kind, int acc, struct IR_VALUE b, int rb, struct IR_ALLOC *al) {
    if (rb >= 0) {
        EMIT(ircg_rex_w(rb, acc), (uint8_t)ircg_arith_rr[kind],
             (uint8_t)(0xC0 | ((rb & 7) << 3) | (acc & 7)));
    } else if (b.k == IRVK_CONST && b.c >= -2147483648LL && b.c <= 2147483647LL) {
        EMIT((uint8_t)(0x48 | ((acc >> 3) & 1)), 0x81,
             (uint8_t)(0xC0 | (ircg_arith_dig[kind] << 3) | (acc & 7)));
        emit_imm(b.c, 4);
    } else if (b.k == IRVK_REG) {
        EMIT((uint8_t)(0x48 | (((acc >> 3) & 1) << 2)), (uint8_t)ircg_arith_rm[kind]);
        x64_rbp_disp(acc & 7, (int)al->slot[b.id]);
    } else {
        ircg_load_to(1, b, al);
        ircg_arith(kind, acc, b, 1, al);
    }
}

static void ircg_prologue(struct IR_ALLOC *al, int is_entry, struct IR_FUNC *f) {
    EMIT(0x55);
    EMIT(0x48, 0x89, 0xE5);
    for (int i = 0; i < al->nsaved; i++) ircg_push(al->saved[i]);
    if (al->framesz > 0) { EMIT(0x48, 0x81, 0xEC); emit_imm(al->framesz, 4); }
    if (is_entry) return;
    static const int preg[6] = { 7, 6, 2, 1, 8, 9 };
    if (f->np > 6) die("IR backend supports at most 6 parameters", 0);
    for (int i = 0; i < f->np && i < 6; i++) ircg_store_from(preg[i], f->preg[i], al);
}

static void ircg_epilogue(struct IR_ALLOC *al) {
    if (al->nsaved) EMIT(0x48, 0x8D, 0x65, (uint8_t)(-(8 * al->nsaved)));
    for (int i = al->nsaved - 1; i >= 0; i--) ircg_pop(al->saved[i]);
    EMIT(0xC9, 0xC3);
}

static int ircg_exit_label = -1;

static void ircg_emit_func(struct IR_FUNC *f, int is_entry) {
    struct IR_ALLOC al;
    ircg_alloc_func(f, &al);

    int blab[IR_BLOCK_MAX], nb = 0;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next) blab[nb++] = emit_new_label();
    int epilab = emit_new_label();

    if (f->naked) {
        for (struct IR_BLOCK *b = f->blocks; b; b = b->next)
            for (struct IR_INSN *in = b->head; in; in = in->next)
                if (in->op == IROP_ALLOCA) die("naked function cannot use a stack frame", 0);
        if (al.slot)
            for (int i = 0; i < al.nreg; i++)
                if (al.slot[i] < 0) { fprintf(stderr, "dbg: naked spill in %s\n", f->nm); die("naked function cannot spill", 0); }
    } else {
        ircg_prologue(&al, is_entry, f);
    }

    int bi = 0;
    for (struct IR_BLOCK *b = f->blocks; b; b = b->next, bi++) {
        emit_put_label(blab[bi]);
        for (struct IR_INSN *in = b->head; in; in = in->next) {
            switch (in->op) {
                case IROP_BIN: {
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : -1;
                    int rb = ircg_val_reg(in->b, &al);
                    switch (in->sub) {
                        case IRBIN_SHL: case IRBIN_SAR: {
                            ircg_load_to(0, in->a, &al);
                            ircg_load_to(1, in->b, &al);
                            EMIT(0x48, 0xD3, (uint8_t)((in->sub == IRBIN_SHL ? 0xE0 : 0xF8) | 0));
                            ircg_store_from(0, in->dst, &al);
                            break;
                        }
                        case IRBIN_SDIV: case IRBIN_SREM: {
                            ircg_load_to(0, in->a, &al);
                            ircg_load_to(1, in->b, &al);
                            EMIT(0x48, 0x99);
                            EMIT(0x48, 0xF7, 0xF9);
                            if (in->sub == IRBIN_SREM) EMIT(0x48, 0x89, 0xD0);
                            ircg_store_from(0, in->dst, &al);
                            break;
                        }
                        case IRBIN_MUL: {
                            int acc = (rd >= 0 && rb != rd) ? rd : 0;
                            ircg_load_to(acc, in->a, &al);
                            if (rb >= 0) {
                                EMIT(ircg_rex_w(acc, rb), 0x0F, 0xAF,
                                     (uint8_t)(0xC0 | ((acc & 7) << 3) | (rb & 7)));
                            } else if (in->b.k == IRVK_CONST && in->b.c >= -2147483648LL && in->b.c <= 2147483647LL) {
                                EMIT(ircg_rex_w(acc, acc), 0x69,
                                     (uint8_t)(0xC0 | ((acc & 7) << 3) | (acc & 7)));
                                emit_imm(in->b.c, 4);
                            } else {
                                ircg_load_to(1, in->b, &al);
                                EMIT((uint8_t)(0x48 | (((acc >> 3) & 1) << 2)), 0x0F, 0xAF,
                                     (uint8_t)(0xC0 | ((acc & 7) << 3) | 1));
                            }
                            ircg_store_from(acc, in->dst, &al);
                            break;
                        }
                        default: {
                            int kind = in->sub == IRBIN_ADD ? 0 : in->sub == IRBIN_SUB ? 1 :
                                       in->sub == IRBIN_AND ? 2 : in->sub == IRBIN_OR ? 3 : 4;
                            int acc = (rd >= 0 && rb != rd) ? rd : 0;
                            ircg_load_to(acc, in->a, &al);
                            ircg_arith(kind, acc, in->b, rb, &al);
                            ircg_store_from(acc, in->dst, &al);
                            break;
                        }
                    }
                    break;
                }
                case IROP_ICMP: {
                    static const int cc[6] = { 0x94, 0x95, 0x9C, 0x9E, 0x9F, 0x9D };
                    ircg_load_to(0, in->a, &al);
                    ircg_arith(5, 0, in->b, ircg_val_reg(in->b, &al), &al);
                    EMIT(0x0F, (uint8_t)cc[in->sub], 0xC0);
                    EMIT(0x0F, 0xB6, 0xC0);
                    ircg_store_from(0, in->dst, &al);
                    break;
                }
                case IROP_LOAD: {
                    ircg_load_to(0, in->a, &al);
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : 0;
                    if (in->ty == IRTY_I8)
                        EMIT((uint8_t)(0x48 | (((rd >> 3) & 1) << 2)), 0x0F, 0xB6, (uint8_t)((rd << 3) & 0x38));
                    else if (in->ty == IRTY_I32)
                        EMIT((uint8_t)(0x40 | (((rd >> 3) & 1) << 2)), 0x8B, (uint8_t)((rd << 3) & 0x38));
                    else
                        EMIT((uint8_t)(0x48 | (((rd >> 3) & 1) << 2)), 0x8B, (uint8_t)((rd << 3) & 0x38));
                    ircg_store_from(rd, in->dst, &al);
                    break;
                }
                case IROP_STORE: {
                    ircg_load_to(0, in->a, &al);
                    ircg_load_to(1, in->b, &al);
                    if (in->ty == IRTY_I8) EMIT(0x88, 0x01);
                    else if (in->ty == IRTY_I32) EMIT(0x89, 0x01);
                    else EMIT(0x48, 0x89, 0x01);
                    break;
                }
                case IROP_ALLOCA: {
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : 0;
                    ircg_lea_rbp(rd, al.region[in->dst]);
                    ircg_store_from(rd, in->dst, &al);
                    break;
                }
                case IROP_PTRADD: {
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : -1;
                    int rb = ircg_val_reg(in->b, &al);
                    int acc = (rd >= 0 && rb != rd) ? rd : 0;
                    ircg_load_to(acc, in->a, &al);
                    ircg_arith(0, acc, in->b, rb, &al);
                    ircg_store_from(acc, in->dst, &al);
                    break;
                }
                case IROP_COPY: {
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : 0;
                    ircg_load_to(rd, in->a, &al);
                    ircg_store_from(rd, in->dst, &al);
                    break;
                }
                case IROP_ZEXT: case IROP_TRUNC: {
                    ircg_load_to(0, in->a, &al);
                    EMIT(0x0F, 0xB6, 0xC0);
                    ircg_store_from(0, in->dst, &al);
                    break;
                }
                case IROP_GADDR: {
                    struct SYM_GLOBAL *g = sym_global_find(in->nm);
                    if (!g) die("undefined global", 0);
                    int rd = (in->dst >= 0 && al.reg[in->dst] >= 0) ? al.reg[in->dst] : 0;
                    ircg_lea_rip(rd, g->off, 2);
                    ircg_store_from(rd, in->dst, &al);
                    break;
                }
                case IROP_CALL: {
                    static const int areg[6] = { 7, 6, 2, 1, 8, 9 };
                    if (in->nargs > 6) die("IR backend supports at most 6 arguments", 0);
                    for (int k = 0; k < in->nargs; k++) ircg_load_to(areg[k], in->args[k], &al);
                    int fi = sym_func_find(in->nm);
                    if (fi < 0) die("call to undefined function", 0);
                    EMIT(0xE8);
                    emit_patch(0, SYM_FUNCS[fi].lab);
                    ircg_store_from(0, in->dst, &al);
                    break;
                }
                case IROP_SYSCALL: {
                    if (in->nargs != 4) die("syscall(nr, a, b, c)", 0);
                    static const int sarg[3] = { 7, 6, 2 };
                    ircg_load_to(0, in->args[0], &al);
                    for (int k = 1; k < 4; k++) ircg_load_to(sarg[k - 1], in->args[k], &al);
                    EMIT(0x0F, 0x05);
                    ircg_store_from(0, in->dst, &al);
                    break;
                }
                case IROP_PRINT: {
                    if (out_freestanding && !out_boot_mode) die("print is unavailable in freestanding mode", 0);
                    ircg_load_to(0, in->a, &al);
                    EMIT(0xE8);
                    emit_patch(0, in->sub ? out_print_str_label : out_print_label);
                    break;
                }
                case IROP_KERN: {
                    switch (in->sub) {
                    case 0: {
                        const uint8_t *blob = (const uint8_t *)in->nm;
                        for (long k = 0; k < in->bytes; k++) EMIT(blob[k]);
                        EMIT(0x31, 0xC0);
                        break;
                    }
                    case 1: EMIT(0xFA); break;
                    case 2: EMIT(0xFB); break;
                    case 3: EMIT(0xF4); break;
                    case 4: EMIT(0x48, 0xCF); break;
                    case 5: case 6: case 7:
                        ircg_load_to(0, in->args[0], &al);
                        if (in->sub == 5) EMIT(0x0F, 0x01, 0x10);
                        else if (in->sub == 6) EMIT(0x0F, 0x01, 0x18);
                        else EMIT(0x0F, 0x22, 0xD8);
                        break;
                    case 8: case 9:
                        ircg_load_to(0, in->args[0], &al);
                        EMIT(0x66, 0x89, 0xC2);
                        if (in->sub == 9) EMIT(0xED);
                        else { EMIT(0xEC); EMIT(0x0F, 0xB6, 0xC0); }
                        break;
                    case 10: case 11:
                        ircg_load_to(0, in->args[1], &al);
                        EMIT(0x50);
                        ircg_load_to(0, in->args[0], &al);
                        EMIT(0x66, 0x89, 0xC2);
                        EMIT(0x58);
                        EMIT(in->sub == 11 ? 0xEF : 0xEE);
                        break;
                    }
                    ircg_store_from(0, in->dst, &al);
                    break;
                }
                case IROP_BR: {
                    int t = 0, i2 = 0;
                    for (struct IR_BLOCK *bb = f->blocks; bb; bb = bb->next, i2++)
                        if (bb->id == in->t1) { t = i2; break; }
                    EMIT(0xE9);
                    emit_rel32(blab[t]);
                    break;
                }
                case IROP_CBR: {
                    ircg_load_to(0, in->a, &al);
                    EMIT(0x48, 0x85, 0xC0);
                    int tt1 = 0, tt2 = 0, i2 = 0;
                    for (struct IR_BLOCK *bb = f->blocks; bb; bb = bb->next, i2++) {
                        if (bb->id == in->t1) tt1 = i2;
                        if (bb->id == in->t2) tt2 = i2;
                    }
                    EMIT(0x0F, 0x84);
                    emit_rel32(blab[tt2]);
                    EMIT(0xE9);
                    emit_rel32(blab[tt1]);
                    break;
                }
                case IROP_RET: {
                    if (in->ty != IRTY_VOID) ircg_load_to(0, in->a, &al);
                    EMIT(0xE9);
                    emit_rel32(is_entry ? ircg_exit_label : epilab);
                    break;
                }
                default: break;
            }
        }
    }
    if (!is_entry) {
        emit_put_label(epilab);
        if (f->naked) EMIT(0xC3);
        else ircg_epilogue(&al);
    }
    ircg_free_alloc(&al);
}

static void ircg_emit_entry(void) {
    if (!out_freestanding) {
        for (int i = 0; i < 8; i++) {
            char nm[8];
            sprintf(nm, "argv%d", i + 1);
            struct SYM_GLOBAL *a = sym_global_find(nm);
            if (!a) continue;
            EMIT(0x48, 0x8B, 0x44, 0x24, (uint8_t)(0x10 + 8 * i));
            EMIT(0x48, 0x89, 0x05);
            emit_patch(2, a->off);
        }
    }
    struct IR_FUNC *fe = ir_funcs;
    while (fe && strcmp(fe->nm, "entry")) fe = fe->next;
    if (fe) {
        ircg_exit_label = emit_new_label();
        ircg_emit_func(fe, 1);
        emit_put_label(ircg_exit_label);
        ircg_exit_label = -1;
    }
    int mi = sym_func_find(out_entry_name ? out_entry_name : "main");
    if (mi >= 0) {
        EMIT(0xE8);
        emit_patch(0, SYM_FUNCS[mi].lab);
        if (out_freestanding) EMIT(0xEB, 0xFE);
        else if (emit_is_pe) { EMIT(0x48, 0x89, 0xC1); emit_call_iat(2); }
        else { EMIT(0x48, 0x89, 0xC7); x64_mov_imm(60); EMIT(0x0F, 0x05); }
    } else if (out_freestanding) {
        EMIT(0xEB, 0xFE);
    } else if (emit_is_pe) {
        EMIT(0x31, 0xC9);
        emit_call_iat(2);
    } else {
        x64_mov_imm(60);
        EMIT(0x31, 0xFF);
        EMIT(0x0F, 0x05);
    }
}

static void ircg_generate(struct AST_NODE *root) {
    out_bin_fmt = (out_format == FMT_BIN);
    if (out_bin_fmt && out_raw_mode) die("IR backend does not support @raw output", 0);
    emit_len = 0;
    sym_nglobal = 0; sym_gsize = 0;
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *n = root->data.block.stmts[i];
        if (n->type != NODE_LET) continue;
        if (sym_nglobal >= (int)(sizeof SYM_GLOBALS / sizeof *SYM_GLOBALS)) die("too many globals", n->line);
        SYM_GLOBALS[sym_nglobal] = (typeof(SYM_GLOBALS[0])){ n->data.let.name, n->data.let.ty, sym_gsize, 0 };
        sym_gsize += type_size(n->data.let.ty);
        sym_nglobal++;
    }
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *fd = root->data.block.stmts[i];
        if (fd->type != NODE_FUNCTION) continue;
        int fi = sym_func_find(fd->data.function.name);
        if (fi < 0) die("undefined function", fd->line);
        SYM_FUNCS[fi].lab = emit_new_label();
    }
    sym_global_hash_build();
    sym_func_hash_build();
    if (out_bin_fmt) { emit_entry_off = emit_len; ircg_emit_entry(); }
    if (!out_freestanding) {
        out_print_label = emit_new_label(); emit_put_label(out_print_label);
        if (emit_is_pe) x64_emit_print_pe(); else x64_emit_print_elf();
        out_print_str_label = emit_new_label(); emit_put_label(out_print_str_label);
        if (emit_is_pe) x64_emit_print_str_pe(); else x64_emit_print_str_elf();
    } else if (out_bin_fmt && out_boot_mode) {
        out_print_label = emit_new_label(); emit_put_label(out_print_label);
        x64_emit_print_bare();
        out_print_str_label = emit_new_label(); emit_put_label(out_print_str_label);
        x64_emit_print_str_bare();
    }
    emit_lit_label = emit_new_label();
    for (int i = 0; i < root->data.block.count; i++) {
        struct AST_NODE *fd = root->data.block.stmts[i];
        if (fd->type != NODE_FUNCTION) continue;
        struct IR_FUNC *ff = ir_funcs;
        while (ff && strcmp(ff->nm, fd->data.function.name)) ff = ff->next;
        if (!ff) die("missing IR function", fd->line);
        emit_put_label(SYM_FUNCS[sym_func_find(fd->data.function.name)].lab);
        ircg_emit_func(ff, 0);
    }
    emit_entry_off = emit_len;
    if (!out_bin_fmt) ircg_emit_entry();
    emit_put_label(emit_lit_label);
    if (parse_nlit) { memcpy(emit_buf + emit_len, PARSE_LITS, parse_nlit); emit_len += parse_nlit; }
    emit_shrink_relayout();
    emit_pcb = (EMIT_PE_SECT_SIZE + 15) & ~15;
    emit_apply_patches();
}

static void x64_reset_state(void) {
    emit_len = 0; emit_entry_off = 0; emit_nlabel = 1; emit_npatch = 0; emit_niat = 0;
    sym_nglobal = 0; sym_gsize = 0; sym_nfunc = 0;
    memset(emit_label_pos, 0, sizeof emit_label_pos);
    memset(SYM_GLOBALS, 0, sizeof SYM_GLOBALS);
    memset(SYM_FUNCS, 0, sizeof SYM_FUNCS);
    memset(EMIT_PATCHES, 0, sizeof EMIT_PATCHES);
    for (int i = 0; i < SYM_HASH_SIZE; i++) { SYM_GLOBAL_HASH[i] = -1; SYM_FUNC_HASH[i] = -1; }
    emit_lit_label = 0; out_print_label = 0; out_print_str_label = 0; emit_pcb = 0;
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
            out_efi_mode = !strcmp(v, "efi");
            if (out_efi_mode) cli_fmt = FMT_PE;
        } else if (!strcmp(a, "-b") && ai + 1 < argc) cli_base = lex_number(argv[++ai]);
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
    if (ol >= 4 && !memcmp(out + ol - 4, ".efi", 4)) { out_format = FMT_PE; out_efi_mode = 1; }
    else out_format = ol >= 4 && !memcmp(out + ol - 4, ".exe", 4) ? FMT_PE : FMT_ELF;

    struct TOKEN *tokens = NULL;
    int tcnt = 0, tcap = 0;
    for (int i = 0; i < nsrc; i++) {
        printf("Compiling %s...\n", argv[ai + i]);
        if (drv_import_seen(argv[ai + i])) continue;
        drv_import_mark(argv[ai + i]);
        lex_load_file(argv[ai + i], &tokens, &tcnt, &tcap);
    }
    PUSH(tokens, tcnt, tcap, lex_make_token(TOK_EOF, "", 0, 0));

    struct PARSE_STATE p = { tokens, tcnt, 0 };
    parse_advance(&p);
    struct AST_NODE *root = parse_program(&p);

    if (cli_emit_ir == 1) { ir_lower_program(root); ir_print(); return 0; }
    if (cli_emit_ir == 2) {
        ir_lower_program(root);
        for (struct IR_FUNC *f = ir_funcs; f; f = f->next) { ir_split_edges(f); ir_prune(f); ir_mem2reg(f); }
        ir_print();
        return 0;
    }

    if (cli_fmt >= 0) out_format = cli_fmt;
    if (cli_base >= 0) out_load_base = cli_base;
    if (cli_entry) out_entry_name = cli_entry;
    if (cli_free >= 0) out_freestanding = cli_free;
    if (out_raw_mode) { out_format = FMT_BIN; out_freestanding = 1; }
    if (out_boot_mode) { out_format = FMT_BIN; out_freestanding = 1; out_load_base = 0x100000; }
    if (out_efi_mode) { out_format = FMT_PE; out_freestanding = 1; }
    if (out_format == FMT_BIN) out_freestanding = 1;
    emit_is_pe = out_format == FMT_PE;
    emit_pe_impsz = out_efi_mode ? 0 : 176;
    if (cli_backend >= 1 && out_efi_mode) die("IR backend does not support EFI output yet", 0);

    if (!out_raw_mode && !getenv("LGC_NO_OPT")) opt_run(root);

    if (cli_backend == 2) {
        x64_generate(root);
        if (out_format == FMT_BIN) out_write_bin(out);
        else if (emit_is_pe) out_write_pe(out);
        else out_write_elf(out);
        x64_reset_state();
    }
    if (cli_backend >= 1) {
        char out2[512];
        if (out_format == FMT_BIN && out_raw_mode) die("IR backend does not support @raw output", 0);
        ir_pipeline(root);
        ircg_generate(root);
        if (cli_backend == 2) {
            snprintf(out2, sizeof out2, "%s.ssa", out);
            if (emit_is_pe) out_write_pe(out2);
            else if (out_format == FMT_BIN) out_write_bin(out2);
            else out_write_elf(out2);
            printf("Generated %s (SSA IR backend)\n", out2);
        } else {
            if (out_format == FMT_BIN) out_write_bin(out);
            else if (emit_is_pe) out_write_pe(out); else out_write_elf(out);
        }
    } else if (cli_backend == 0) {
        x64_generate(root);
        if (out_format == FMT_BIN) out_write_bin(out);
        else if (emit_is_pe) out_write_pe(out);
        else out_write_elf(out);
    }

    printf("Generated %s (%s x86-64)\n", out,
           out_format == FMT_BIN ? "flat binary" : emit_is_pe ? "PE32+" : "ELF");
    return 0;
}

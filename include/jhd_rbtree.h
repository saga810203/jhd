/*
 * jhd_rbtree.h
 *
 *  Created on: 2018年5月19日
 *      Author: root
 */

#ifndef JHD_RBTREE_H_
#define JHD_RBTREE_H_

#include <jhd_config.h>

typedef struct jhd_rbtree_node_s jhd_rbtree_node_t;

struct jhd_rbtree_node_s {
	uint64_t key;
	jhd_rbtree_node_t *left;
	jhd_rbtree_node_t *right;
	jhd_rbtree_node_t *parent;
	u_char color;
	u_char data;
};

typedef struct jhd_rbtree_s jhd_rbtree_t;

typedef void (*jhd_rbtree_insert_pt)(jhd_rbtree_node_t *root,
		jhd_rbtree_node_t *node, jhd_rbtree_node_t *sentinel);

struct jhd_rbtree_s {
	jhd_rbtree_node_t *root;
	jhd_rbtree_node_t *sentinel;
	jhd_rbtree_insert_pt insert;
};

#define jhd_rbtree_init(tree, s, i)                                           \
    jhd_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i

void jhd_rbtree_insert(jhd_rbtree_t *tree, jhd_rbtree_node_t *node);
void jhd_rbtree_delete(jhd_rbtree_t *tree, jhd_rbtree_node_t *node);
void jhd_rbtree_insert_value(jhd_rbtree_node_t *root, jhd_rbtree_node_t *node,
		jhd_rbtree_node_t *sentinel);
void jhd_rbtree_insert_timer_value(jhd_rbtree_node_t *root,
		jhd_rbtree_node_t *node, jhd_rbtree_node_t *sentinel);
jhd_rbtree_node_t *jhd_rbtree_next(jhd_rbtree_t *tree, jhd_rbtree_node_t *node);

#define jhd_rbt_red(node)               ((node)->color = 1)
#define jhd_rbt_black(node)             ((node)->color = 0)
#define jhd_rbt_is_red(node)            ((node)->color)
#define jhd_rbt_is_black(node)          (!jhd_rbt_is_red(node))
#define jhd_rbt_copy_color(n1, n2)      (n1->color = n2->color)

/* a sentinel must be black */

#define jhd_rbtree_sentinel_init(node)  jhd_rbt_black(node)

static jhd_inline jhd_rbtree_node_t *
jhd_rbtree_min(jhd_rbtree_node_t *node, jhd_rbtree_node_t *sentinel) {
	while (node->left != sentinel) {
		node = node->left;
	}
	return node;
}

#endif /* JHD_RBTREE_H_ */

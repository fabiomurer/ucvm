#pragma once

#include <stddef.h>
#include <stdbool.h>

// Intrusive doubly linked list node
struct dlist_head {
	struct dlist_head *next, *prev;
};

// Initialize a new list head (sentinel node)
#define DLIST_HEAD_INIT(name) { &(name), &(name) }

#define DLIST_HEAD(name) struct dlist_head name = DLIST_HEAD_INIT(name)

// Initialize a dlist_head structure (usually for struct members)
void dlist_init(struct dlist_head *list);

// Insert a new entry after head (at beginning)
void dlist_add(struct dlist_head *new, struct dlist_head *head);

// Insert a new entry before head (at end)
void dlist_add_tail(struct dlist_head *new, struct dlist_head *head);

// Remove an entry from the list and reinitialize it
void dlist_del(struct dlist_head *entry);

// Check if list is empty
bool dlist_empty(const struct dlist_head *head);

void dlist_push(struct dlist_head *new, struct dlist_head *head);

struct dlist_head *dlist_pop(struct dlist_head *head);

// Get the struct for this entry
#define dlist_entry(ptr, type, member) ((type *)((char *)(ptr) - (size_t)offsetof(type, member)))

// Iterate from first to last (forward)
#define dlist_for_each(pos, head) for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

// Iterate from last to first (reverse)
#define dlist_for_each_reverse(pos, head) \
	for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

// Safe iteration from first to last (can remove pos during loop)
#define dlist_for_each_safe(pos, n, head)                              \
	for ((pos) = (head)->next, (n) = (pos)->next; (pos) != (head); \
	     (pos) = (n), (n) = (pos)->next)

// Safe iteration from last to first (can remove pos during loop)
#define dlist_for_each_reverse_safe(pos, n, head)                      \
	for ((pos) = (head)->prev, (n) = (pos)->prev; (pos) != (head); \
	     (pos) = (n), (n) = (pos)->prev)

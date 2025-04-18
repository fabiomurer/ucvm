#include "intrusive_dlist.h"

void dlist_init(struct dlist_head *list)
{
	list->next = list;
	list->prev = list;
}

static void __dlist_add(struct dlist_head *new, struct dlist_head *prev, struct dlist_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

void dlist_add(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head, head->next);
}

void dlist_add_tail(struct dlist_head *new, struct dlist_head *head)
{
	__dlist_add(new, head->prev, head);
}

void dlist_push(struct dlist_head *new, struct dlist_head *head)
{
	dlist_add(new, head);
}

struct dlist_head *dlist_pop(struct dlist_head *head)
{
	if (dlist_empty(head)) {
		return nullptr;
	}
	struct dlist_head *first = head->next;
	dlist_del(first);
	return first;
}

static void __dlist_del(struct dlist_head *prev, struct dlist_head *next)
{
	next->prev = prev;
	prev->next = next;
}

void dlist_del(struct dlist_head *entry)
{
	__dlist_del(entry->prev, entry->next);
	dlist_init(entry);
}

bool dlist_empty(const struct dlist_head *head)
{
	return head->next == head;
}

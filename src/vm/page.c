#include "vm/page.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// We got some help from A.8.5 Hash Table Example
unsigned
upage_hash (const struct hash_elem *_e, void *aux)
{
  const struct sup_pte *e = hash_entry (_e, struct sup_pte, elem);
  return hash_bytes (&e->upage, sizeof e->upage);
}

bool
upage_less (const struct hash_elem *_a, const struct hash_elem *_b, void *aux)
{
  const struct sup_pte *a = hash_entry (_a, struct sup_pte, elem);
  const struct sup_pte *b = hash_entry (_b, struct sup_pte, elem);
  return a->upage < b->upage;
}


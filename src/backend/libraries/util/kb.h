// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: kb.h
 * Brief: Knowledge base management API - Redis backend.
 *  
 * Copyright:
 * Copyright (C) 2014-2019 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 * 
 */

#ifndef _GVM_KB_H
#define _GVM_KB_H

#include "../base/nvti.h" /* for nvti_t */

#include <assert.h>
#include <stddef.h>    /* for NULL */
#include <sys/types.h> /* for size_t */

/**
 * @brief Default KB location.
 */
#define KB_PATH_DEFAULT "/usr/local/var/run/redis.sock"

/**
 * @brief Possible type of a kb_item.
 */
enum kb_item_type
{
  KB_TYPE_UNSPEC, /**< Ignore the value (name/presence test).              */
  KB_TYPE_INT,    /**< The kb_items v should then be interpreted as int.   */
  KB_TYPE_STR,    /**< The kb_items v should then be interpreted as char*. */
  /* -- */
  KB_TYPE_CNT,
};

/**
 * @brief Possible positions of nvt values in cache list.
 */
enum kb_nvt_pos
{
  NVT_FILENAME_POS,
  NVT_REQUIRED_KEYS_POS,
  NVT_MANDATORY_KEYS_POS,
  NVT_EXCLUDED_KEYS_POS,
  NVT_REQUIRED_UDP_PORTS_POS,
  NVT_REQUIRED_PORTS_POS,
  NVT_DEPENDENCIES_POS,
  NVT_TAGS_POS,
  NVT_CVES_POS,
  NVT_BIDS_POS,
  NVT_XREFS_POS,
  NVT_CATEGORY_POS,
  NVT_TIMEOUT_POS,
  NVT_FAMILY_POS,
  NVT_NAME_POS,
  NVT_TIMESTAMP_POS,
  NVT_OID_POS,
};

/**
 * @brief Knowledge base item (defined by name, type (int/char*) and value).
 *        Implemented as a singly linked list
 */
struct kb_item
{
  enum kb_item_type type; /**< One of KB_TYPE_INT or KB_TYPE_STR. */

  union /**< Store a char or an int. */
  {
    char *v_str; /**< Hold an str value for this kb item. */
    int v_int;   /**< Hold an int value for this kb item. */
  };             /**< Value of this knowledge base item. */

  size_t len;           /**< Length of string. */
  struct kb_item *next; /**< Next item in list. */

  size_t namelen; /**< Name length (including final NULL byte). */
  char name[0];   /**< Name of this knowledge base item.  */
};

struct kb_operations;

/**
 * @brief Top-level KB. This is to be inherited by KB implementations.
 */
struct kb
{
  const struct kb_operations *kb_ops; /**< KB vtable. */
};

/**
 * @brief type abstraction to hide KB internals.
 */
typedef struct kb *kb_t;

/**
 * @brief KB interface. Functions provided by an implementation. All functions
 *        have to be provided, there is no default/fallback. These functions
 *        should be called via the corresponding static inline wrappers below.
 *        See the wrappers for the documentation.
 */
struct kb_operations
{
  /* ctor/dtor */
  int (*kb_new) (kb_t *, const char *);             /**< New KB. */
  int (*kb_delete) (kb_t);                          /**< Delete KB. */
  kb_t (*kb_find) (const char *, const char *);     /**< Find KB. */
  kb_t (*kb_direct_conn) (const char *, const int); /**< Connect to a KB. */

  /* Actual kb operations */
  /**
   * Function provided by an implementation to get a single kb element.
   */
  struct kb_item *(*kb_get_single) (kb_t, const char *, enum kb_item_type);
  /**
   * Function provided by an implementation to get single kb str item.
   */
  char *(*kb_get_str) (kb_t, const char *);
  /**
   * Function provided by an implementation to get single kb int item.
   */
  int (*kb_get_int) (kb_t, const char *);
  /**
   * Function provided by an implementation to get field of NVT.
   */
  char *(*kb_get_nvt) (kb_t, const char *, enum kb_nvt_pos);
  /**
   * Function provided by an implementation to get a full NVT.
   */
  nvti_t *(*kb_get_nvt_all) (kb_t, const char *);
  /**
   * Function provided by an implementation to get list of OIDs.
   */
  GSList *(*kb_get_nvt_oids) (kb_t);
  /**
   * Function provided by an implementation to push a new value under a key.
   */
  int (*kb_push_str) (kb_t, const char *, const char *);
  /**
   * Function provided by an implementation to pop a str under a key.
   */
  char *(*kb_pop_str) (kb_t, const char *);
  /**
   * Function provided by an implementation to get all items stored
   * under a given name.
   */
  struct kb_item *(*kb_get_all) (kb_t, const char *);
  /**
   * Function provided by an implementation to get all items stored
   * under a given pattern.
   */
  struct kb_item *(*kb_get_pattern) (kb_t, const char *);
  /**
   * Function provided by an implementation to count all items stored
   * under a given pattern.
   */
  size_t (*kb_count) (kb_t, const char *);
  /**
   * Function provided by an implementation to insert (append) a new entry
   * under a given name.
   */
  int (*kb_add_str) (kb_t, const char *, const char *, size_t);
  /**
   * Function provided by an implementation to insert (append) a new
   * unique entry under a given name.
   */
  int (*kb_add_str_unique) (kb_t, const char *, const char *, size_t);
  /**
   * Function provided by an implementation to get (replace) a new entry
   * under a given name.
   */
  int (*kb_set_str) (kb_t, const char *, const char *, size_t);
  /**
   * Function provided by an implementation to insert (append) a new entry
   * under a given name.
   */
  int (*kb_add_int) (kb_t, const char *, int);
  /**
   * Function provided by an implementation to insert (append) a new
   * unique entry under a given name.
   */
  int (*kb_add_int_unique) (kb_t, const char *, int);
  /**
   * Function provided by an implementation to get (replace) a new entry
   * under a given name.
   */
  int (*kb_set_int) (kb_t, const char *, int);
  /**
   * Function provided by an implementation to
   * insert a new nvt.
   */
  int (*kb_add_nvt) (kb_t, const nvti_t *, const char *);
  /**
   * Function provided by an implementation to delete all entries
   * under a given name.
   */
  int (*kb_del_items) (kb_t, const char *);

  /* Utils */
  int (*kb_save) (kb_t);                /**< Save all kb content. */
  int (*kb_lnk_reset) (kb_t);           /**< Reset connection to KB. */
  int (*kb_flush) (kb_t, const char *); /**< Flush redis DB. */
  int (*kb_get_kb_index) (kb_t);        /**< Get kb index. */
};

/**
 * @brief Default KB operations.
 *        No selection mechanism is provided yet since there's only one
 *        implementation (redis-based).
 */
extern const struct kb_operations *KBDefaultOperations;

/**
 * @brief Release a KB item (or a list).
 */
void
kb_item_free (struct kb_item *);

/**
 * @brief Initialize a new Knowledge Base object.
 * @param[in] kb  Reference to a kb_t to initialize.
 * @param[in] kb_path   Path to KB.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_new (kb_t *kb, const char *kb_path)
{
  assert (kb);
  assert (KBDefaultOperations);
  assert (KBDefaultOperations->kb_new);

  *kb = NULL;

  return KBDefaultOperations->kb_new (kb, kb_path);
}

/**
 * @brief Connect to a Knowledge Base object which has the given kb_index.
 * @param[in] kb_path   Path to KB.
 * @param[in] kb_index       DB index
 * @return Knowledge Base object, NULL otherwise.
 */
static inline kb_t
kb_direct_conn (const char *kb_path, const int kb_index)
{
  assert (KBDefaultOperations);
  assert (KBDefaultOperations->kb_direct_conn);

  return KBDefaultOperations->kb_direct_conn (kb_path, kb_index);
}

/**
 * @brief Find an existing Knowledge Base object with key.
 * @param[in] kb_path   Path to KB.
 * @param[in] key       Marker key to search for in KB objects.
 * @return Knowledge Base object, NULL otherwise.
 */
static inline kb_t
kb_find (const char *kb_path, const char *key)
{
  assert (KBDefaultOperations);
  assert (KBDefaultOperations->kb_find);

  return KBDefaultOperations->kb_find (kb_path, key);
}

/**
 * @brief Delete all entries and release ownership on the namespace.
 * @param[in] kb  KB handle to release.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_delete (kb_t kb)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_delete);

  return kb->kb_ops->kb_delete (kb);
}

/**
 * @brief Get a single KB element.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @param[in] type  Desired element type.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static inline struct kb_item *
kb_item_get_single (kb_t kb, const char *name, enum kb_item_type type)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_single);

  return kb->kb_ops->kb_get_single (kb, name, type);
}

/**
 * @brief Get a single KB string item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static inline char *
kb_item_get_str (kb_t kb, const char *name)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_str);

  return kb->kb_ops->kb_get_str (kb, name);
}

/**
 * @brief Get a single KB integer item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static inline int
kb_item_get_int (kb_t kb, const char *name)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_int);

  return kb->kb_ops->kb_get_int (kb, name);
}

/**
 * @brief Get all items stored under a given name.
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] name  Name of the elements to retrieve.
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static inline struct kb_item *
kb_item_get_all (kb_t kb, const char *name)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_all);

  return kb->kb_ops->kb_get_all (kb, name);
}

/**
 * @brief Get all items stored under a given pattern.
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] pattern  '*' pattern of the elements to retrieve.
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static inline struct kb_item *
kb_item_get_pattern (kb_t kb, const char *pattern)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_pattern);

  return kb->kb_ops->kb_get_pattern (kb, pattern);
}

/**
 * @brief Push a new value under a given key.
 * @param[in] kb    KB handle where to store the item.
 * @param[in] name  Key to push to.
 * @param[in] value Value to push.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_push_str (kb_t kb, const char *name, const char *value)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_push_str);

  return kb->kb_ops->kb_push_str (kb, name, value);
}

/**
 * @brief Pop a single KB string item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static inline char *
kb_item_pop_str (kb_t kb, const char *name)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_pop_str);

  return kb->kb_ops->kb_pop_str (kb, name);
}

/**
 * @brief Count all items stored under a given pattern.
 *
 * @param[in] kb  KB handle where to count the items.
 * @param[in] pattern  '*' pattern of the elements to count.
 *
 * @return Count of items.
 */
static inline size_t
kb_item_count (kb_t kb, const char *pattern)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_count);

  return kb->kb_ops->kb_count (kb, pattern);
}

/**
 * @brief Insert (append) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_add_str (kb_t kb, const char *name, const char *str, size_t len)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_add_str);

  return kb->kb_ops->kb_add_str (kb, name, str, len);
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_add_str_unique (kb_t kb, const char *name, const char *str, size_t len)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_add_str_unique);

  return kb->kb_ops->kb_add_str_unique (kb, name, str, len);
}

/**
 * @brief Set (replace) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_set_str (kb_t kb, const char *name, const char *str, size_t len)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_set_str);

  return kb->kb_ops->kb_set_str (kb, name, str, len);
}

/**
 * @brief Insert (append) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_add_int (kb_t kb, const char *name, int val)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_add_int);

  return kb->kb_ops->kb_add_int (kb, name, val);
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_add_int_unique (kb_t kb, const char *name, int val)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_add_int_unique);

  return kb->kb_ops->kb_add_int_unique (kb, name, val);
}

/**
 * @brief Set (replace) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_item_set_int (kb_t kb, const char *name, int val)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_set_int);

  return kb->kb_ops->kb_set_int (kb, name, val);
}

/**
 * @brief Insert a new nvt.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] nvt       nvt to store.
 * @param[in] filename  Path to nvt to store.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_nvt_add (kb_t kb, const nvti_t *nvt, const char *filename)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_add_nvt);

  return kb->kb_ops->kb_add_nvt (kb, nvt, filename);
}

/**
 * @brief Get field of a NVT.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get from.
 * @param[in] position  Position of field to get.
 * @return Value of field, NULL otherwise.
 */
static inline char *
kb_nvt_get (kb_t kb, const char *oid, enum kb_nvt_pos position)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_nvt);

  return kb->kb_ops->kb_get_nvt (kb, oid, position);
}

/**
 * @brief Get a full NVT.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get.
 * @return nvti_t of NVT, NULL otherwise.
 */
static inline nvti_t *
kb_nvt_get_all (kb_t kb, const char *oid)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_nvt_all);

  return kb->kb_ops->kb_get_nvt_all (kb, oid);
}

/**
 * @brief Get list of NVT OIDs.
 * @param[in] kb        KB handle where NVTs are stored.
 * @return Linked-list of OIDs, NULL otherwise.
 */
static inline GSList *
kb_nvt_get_oids (kb_t kb)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_nvt_oids);

  return kb->kb_ops->kb_get_nvt_oids (kb);
}

/**
 * @brief Delete all entries under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_del_items (kb_t kb, const char *name)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_del_items);

  return kb->kb_ops->kb_del_items (kb, name);
}

/**
 * @brief Save all the KB's content.
 * @param[in] kb        KB handle.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_save (kb_t kb)
{
  int rc = 0;

  assert (kb);
  assert (kb->kb_ops);

  if (kb->kb_ops->kb_save != NULL)
    rc = kb->kb_ops->kb_save (kb);

  return rc;
}

/**
 * @brief Reset connection to the KB. This is called after each fork() to make
 *        sure connections aren't shared between concurrent processes.
 * @param[in] kb  KB handle.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_lnk_reset (kb_t kb)
{
  int rc = 0;

  assert (kb);
  assert (kb->kb_ops);

  if (kb->kb_ops->kb_lnk_reset != NULL)
    rc = kb->kb_ops->kb_lnk_reset (kb);

  return rc;
}

/**
 * @brief Flush all the KB's content. Delete all namespaces.
 * @param[in] kb        KB handle.
 * @param[in] except    Don't flush DB with except key.
 * @return 0 on success, non-null on error.
 */
static inline int
kb_flush (kb_t kb, const char *except)
{
  int rc = 0;

  assert (kb);
  assert (kb->kb_ops);

  if (kb->kb_ops->kb_flush != NULL)
    rc = kb->kb_ops->kb_flush (kb, except);

  return rc;
}

/**
 * @brief Return the kb index
 * @param[in] kb KB handle.
 * @return kb_index on success, null on error.
 */
static inline int
kb_get_kb_index (kb_t kb)
{
  assert (kb);
  assert (kb->kb_ops);
  assert (kb->kb_ops->kb_get_kb_index);

  return kb->kb_ops->kb_get_kb_index (kb);
}

#endif

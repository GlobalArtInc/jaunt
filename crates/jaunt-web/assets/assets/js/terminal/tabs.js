export function createTabs({ max = null } = {}) {
  let limit = max;
  let items = [];
  let activeId = null;

  function indexOf(id) {
    return items.findIndex((item) => item.id === id);
  }

  return {
    items: () => items.slice(),
    count: () => items.length,
    max: () => limit,
    setMax(value) {
      limit = value;
    },
    atLimit: () => limit !== null && items.length >= limit,
    activeId: () => activeId,
    get: (id) => items.find((item) => item.id === id) || null,
    active: () => items.find((item) => item.id === activeId) || null,
    add(item) {
      if (limit !== null && items.length >= limit) {
        return false;
      }
      items.push(item);
      activeId = item.id;
      return true;
    },
    activate(id) {
      if (indexOf(id) === -1) {
        return false;
      }
      activeId = id;
      return true;
    },
    step(delta) {
      if (items.length === 0) {
        return null;
      }
      const from = Math.max(0, indexOf(activeId));
      const next = items[(from + delta + items.length) % items.length];
      activeId = next.id;
      return next.id;
    },
    close(id) {
      const index = indexOf(id);
      if (index === -1) {
        return null;
      }
      const [closed] = items.splice(index, 1);
      if (activeId === id) {
        activeId = items.length === 0 ? null : items[Math.min(index, items.length - 1)].id;
      }
      return { closed, next: activeId };
    },
    idsWhere: (test) => items.filter(test).map((item) => item.id),
  };
}

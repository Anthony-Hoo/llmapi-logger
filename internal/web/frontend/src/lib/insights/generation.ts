// A generation counter lets an async response tell whether the request that
// started it has been superseded (a filter or sort changed while it was in
// flight). Responses of an older generation must be discarded.
export interface Generation {
  advance(): number;
  current(): number;
  isCurrent(value: number): boolean;
}

export function createGeneration(): Generation {
  let value = 0;
  return {
    advance: () => ++value,
    current: () => value,
    isCurrent: (candidate) => candidate === value,
  };
}

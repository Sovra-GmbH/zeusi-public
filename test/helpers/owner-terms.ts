// Public operator-contact rule for site and served-copy tests: exactly
// hello@sovra.ch is allowed; any other local part at sovra.ch is not.
const OPERATOR_ADDRESS = String.raw`(?:^|[^A-Za-z0-9._%+-])(?!hello@)[A-Za-z0-9._%+-]*@sovra\.ch`;
const OPERATOR_ADDRESS_RE = new RegExp(OPERATOR_ADDRESS, 'i');

/** True when `text` contains a non-role address at the operator domain. */
export function hasNonRoleOperatorAddress(text: string): boolean {
  return OPERATOR_ADDRESS_RE.test(text);
}

export const ROLE_EMAIL = 'hello@sovra.ch';

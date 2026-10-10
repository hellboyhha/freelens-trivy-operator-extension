// Page and menu identifiers, shared by the registrations in index.tsx and the pages
// that link to each other.

export const ROOT_MENU_ID = "trivy";

export const OVERVIEW_PAGE_ID = "trivy-overview";
export const VULNERABILITIES_PAGE_ID = "trivy-vulnerabilities";
export const MISCONFIGURATIONS_PAGE_ID = "trivy-misconfigurations";
export const SECRETS_PAGE_ID = "trivy-secrets";
export const SBOMS_PAGE_ID = "trivy-sboms";
export const COMPLIANCE_PAGE_ID = "trivy-compliance";

/**
 * The URL of one of the extension's pages. The host mounts them under
 * `/extension/<name with @ dropped and / as -->/<pageId>`. Pages navigate through links
 * to these URLs.
 */
export function extensionPageUrl(extensionName: string, pageId: string): string {
  return `/extension/${extensionName.replace(/^@/, "").replace(/\//g, "--")}/${pageId}`;
}

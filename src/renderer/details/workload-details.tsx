// The "Trivy Operator" section the extension adds to the drawer of a Pod or a workload: one card per
// container with what the operator found, a card for the configuration, and a dashed card for
// a container nobody scanned yet. Each card links to its report.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import { maybe } from "../../common/utils";
import { ConfigAuditReport, ExposedSecretReport, VulnerabilityReport } from "../api/trivy";
import { countFixable, imageOf, resourceOf, severityCounts, worstIssue } from "../api/trivy/report-model";
import { withErrorPage } from "../components/error-page";
import { formatAge } from "../components/format";
import { RescanAction } from "../components/rescan-action";
import { SeverityCount, SeverityStyles } from "../components/severity-count";
import { Fixable, Muted, SeverityBar, UiStyles } from "../components/ui";
import { type LoadableStore, useLoadedStores } from "../components/use-loaded-stores";
import { containersOf, reportsFor, targetsFor, workloadCards } from "../components/workload-match";
import styles from "./report-details.module.scss";
import stylesInline from "./report-details.module.scss?inline";

const { observer } = MobxReact;

const {
  Component: { DrawerTitle, MaybeLink },
  Navigation: { getDetailsUrl },
} = Renderer;

interface StoreLike extends LoadableStore {
  items: any[];
}

const storeOf = (kind: { getStore(): unknown }) => maybe(() => kind.getStore()) as StoreLike | null;

function Counts({ summary }: { summary?: Parameters<typeof severityCounts>[0] }) {
  const counts = severityCounts(summary);
  return (
    <>
      {(["critical", "high"] as const).map((key) => (
        <span key={key}>
          <SeverityCount severity={key} count={counts[key]} /> {key}
        </span>
      ))}
    </>
  );
}

export const WorkloadDetails = observer(
  (props: Renderer.Component.KubeObjectDetailsProps<any> & { extension: Renderer.LensExtension }) =>
    withErrorPage(props, () => {
      const { object } = props;
      const stores = {
        vulnerabilities: storeOf(VulnerabilityReport),
        secrets: storeOf(ExposedSecretReport),
        configAudits: storeOf(ConfigAuditReport),
      };
      const namespace = object?.metadata?.namespace;
      useLoadedStores(
        Object.entries(stores).map(([label, store]) => ({
          label,
          store,
          namespaces: namespace ? [namespace] : undefined,
        })),
      );

      // No Trivy Operator CRDs in this cluster: the section has nothing to say.
      if (!object || !stores.vulnerabilities) return <></>;

      const targets = targetsFor(object);
      const cards = workloadCards(containersOf(object), {
        vulnerabilities: reportsFor(stores.vulnerabilities.items, targets),
        secrets: reportsFor(stores.secrets?.items ?? [], targets),
        configs: reportsFor(stores.configAudits?.items ?? [], targets),
      });
      const none = cards.containers.length === 0 && cards.configs.length === 0;
      const reports = [
        ...reportsFor(stores.vulnerabilities.items, targets),
        ...reportsFor(stores.secrets?.items ?? [], targets),
        ...reportsFor(stores.configAudits?.items ?? [], targets),
      ];

      return (
        <>
          <style>{stylesInline}</style>
          <UiStyles />
          <SeverityStyles />
          <DrawerTitle>Trivy Operator</DrawerTitle>
          <RescanAction
            items={reports}
            label="Rescan workload"
            workload={{ kind: object.kind ?? "", name: object.metadata?.name ?? "", namespace: namespace ?? "" }}
          />
          {none ? <Muted>No Trivy Operator reports for this workload yet.</Muted> : null}

          {cards.containers.map(({ name, vulnerabilities: report, secrets, scanned }) =>
            scanned && report ? (
              <div key={name} className={styles.wcard}>
                <div className={styles.wtitle}>
                  <b>{name}</b>
                  <span className={styles.versions}>{imageOf(report.report?.artifact)}</span>
                  <MaybeLink to={getDetailsUrl(report.selfLink)}>View report →</MaybeLink>
                </div>
                <SeverityBar counts={severityCounts(report.report?.summary)} />
                <div className={styles.wrow}>
                  <Counts summary={report.report?.summary} />
                  {countFixable(report.report?.vulnerabilities) > 0 ? (
                    <Fixable>{countFixable(report.report?.vulnerabilities)} fixable</Fixable>
                  ) : null}
                  <span style={{ marginLeft: "auto" }}>
                    <Muted>scanned {formatAge(report.report?.updateTimestamp)} ago</Muted>
                  </span>
                </div>
                {secrets ? (
                  <div className={styles.wrow}>
                    <MaybeLink to={getDetailsUrl(secrets.selfLink)}>
                      {Object.values(severityCounts(secrets.report?.summary)).reduce((a, b) => a + b, 0)} exposed
                      secret(s) →
                    </MaybeLink>
                  </div>
                ) : null}
              </div>
            ) : (
              <div key={name} className={[styles.wcard, styles.wcardMissing].join(" ")}>
                <div className={styles.wtitle}>
                  <b>{name}</b>
                  <Muted>not scanned yet</Muted>
                </div>
                <Muted>The operator has not reached this container. Scans usually finish within a few minutes.</Muted>
              </div>
            ),
          )}

          {cards.configs.map((report) => {
            const issue = worstIssue(report.report?.checks);
            return (
              <div key={report.getId()} className={styles.wcard}>
                <div className={styles.wtitle}>
                  <b>Configuration</b>
                  <Muted>{resourceOf(report.metadata).kind}</Muted>
                  <MaybeLink to={getDetailsUrl(report.selfLink)}>View report →</MaybeLink>
                </div>
                <div className={styles.wrow}>
                  <Counts summary={report.report?.summary} />
                  {issue ? <Muted>{issue.title}</Muted> : <Fixable>no failed checks</Fixable>}
                </div>
              </div>
            );
          })}
        </>
      );
    }),
);

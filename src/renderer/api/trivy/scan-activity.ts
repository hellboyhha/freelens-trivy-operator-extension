// Reads the operator's scan Jobs and their pods. Read-only: two list calls with a label selector.

import { Renderer } from "@freelensapp/extensions";
import { maybe } from "../../../common/utils";
import { type Activity, type JobLike, OPERATOR_LABEL_SELECTOR, type PodLike } from "./scan-status-model";

const query = { labelSelector: OPERATOR_LABEL_SELECTOR };

/**
 * The scan Jobs and pods in every namespace, or null when they cannot be read (no permission, or the
 * cluster is unreachable): the page then keeps what it last knew instead of guessing.
 */
export async function fetchScanActivity(): Promise<Activity | null> {
  const jobApi = maybe(() => Renderer.K8sApi.jobApi);
  const podsApi = maybe(() => Renderer.K8sApi.podsApi);
  if (!jobApi || !podsApi) return null;
  try {
    const [jobs, pods] = await Promise.all([jobApi.list({}, query), podsApi.list({}, query)]);
    return { jobs: (jobs ?? []) as unknown as JobLike[], pods: (pods ?? []) as unknown as PodLike[] };
  } catch {
    return null;
  }
}

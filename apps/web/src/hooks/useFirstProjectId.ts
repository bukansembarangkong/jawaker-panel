import { useEffect, useState } from 'react';
import { api } from '../api/client';

/**
 * Returns the first project's UUID from GET /api/v1/projects.
 * Returns null while loading or if no projects exist.
 */
export function useFirstProjectId(): string | null {
  const [projectId, setProjectId] = useState<string | null>(null);
  useEffect(() => {
    api.listProjects({ limit: 1 }).then((page) => {
      if (page.projects?.length > 0) setProjectId(page.projects[0].id);
    }).catch(() => { /* silently fail; page handles its own errors */ });
  }, []);
  return projectId;
}

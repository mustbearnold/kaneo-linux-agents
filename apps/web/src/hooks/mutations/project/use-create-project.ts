import { useMutation } from "@tanstack/react-query";
import createProject from "@/fetchers/project/create-project";

function useCreateProject({
  name,
  slug,
  workspaceId,
  icon,
  description,
  localPath,
}: {
  name: string;
  slug: string;
  workspaceId: string;
  icon: string;
  description: string;
  localPath: string;
}) {
  return useMutation({
    mutationFn: () =>
      createProject({ name, slug, workspaceId, icon, description, localPath }),
  });
}

export default useCreateProject;

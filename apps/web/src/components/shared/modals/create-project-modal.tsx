import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { FolderOpen } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Textarea } from "@/components/ui/textarea";
import icons from "@/constants/project-icons";
import useCreateProject from "@/hooks/mutations/project/use-create-project";
import useActiveWorkspace from "@/hooks/queries/workspace/use-active-workspace";
import { cn } from "@/lib/cn";
import generateProjectSlug from "@/lib/generate-project-id";
import { pickProjectFolder } from "@/lib/tauri";
import { toast } from "@/lib/toast";

type CreateProjectModalProps = {
  open: boolean;
  onClose: () => void;
};

function CreateProjectModal({ open, onClose }: CreateProjectModalProps) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [slug, setSlug] = useState("");
  const [selectedIcon, setSelectedIcon] = useState("Layout");
  const [iconPopoverOpen, setIconPopoverOpen] = useState(false);
  const [iconSearch, setIconSearch] = useState("");
  const [isPickingFolder, setIsPickingFolder] = useState(false);
  const queryClient = useQueryClient();
  const { data: workspace } = useActiveWorkspace();
  const { mutateAsync } = useCreateProject({
    name,
    slug,
    workspaceId: workspace?.id ?? "",
    icon: selectedIcon,
    description,
    localPath,
  });
  const SelectedIcon =
    icons[selectedIcon as keyof typeof icons] || icons.Layout;
  const filteredIcons = Object.entries(icons).filter(([iconName]) =>
    iconName.toLowerCase().includes(iconSearch.trim().toLowerCase()),
  );
  const navigate = useNavigate();

  const handleClose = () => {
    setName("");
    setDescription("");
    setLocalPath("");
    setSlug("");
    setSelectedIcon("Layout");
    setIconPopoverOpen(false);
    setIconSearch("");
    setIsPickingFolder(false);
    onClose();
  };

  const handlePickFolder = async () => {
    setIsPickingFolder(true);
    try {
      const selected = await pickProjectFolder();
      if (selected) setLocalPath(selected);
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Couldn't open the local folder picker.",
      );
    } finally {
      setIsPickingFolder(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !localPath.trim()) return;

    try {
      const { id } = await mutateAsync();
      toast.success("Project created successfully");
      await queryClient.invalidateQueries({ queryKey: ["projects"] });

      navigate({
        to: "/dashboard/workspace/$workspaceId/project/$projectId/board",
        params: {
          workspaceId: workspace?.id ?? "",
          projectId: id,
        },
      });

      handleClose();
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("common:modals.createProject.errorToast"),
      );
    }
  };

  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newName = e.target.value;
    setName(newName);
    setSlug(generateProjectSlug(newName));
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-lg" showCloseButton={false}>
        <DialogHeader className="px-3 pt-4 pb-1 gap-1.5">
          <DialogTitle className="sr-only">
            {t("common:modals.createProject.title")}
          </DialogTitle>
          <Breadcrumb>
            <BreadcrumbList className="gap-1 text-xs">
              <BreadcrumbItem className="text-muted-foreground font-medium tracking-wide">
                {workspace?.name?.toUpperCase() ||
                  t("common:modals.createProject.workspaceFallback")}
              </BreadcrumbItem>
              <BreadcrumbSeparator className="[&>svg]:size-3.5" />
              <BreadcrumbItem className="text-foreground font-medium">
                {t("common:modals.createProject.breadcrumbNew")}
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <DialogDescription className="sr-only">
            {t("common:modals.createProject.description")}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-6 px-3 pt-2">
            <Popover
              open={iconPopoverOpen}
              onOpenChange={(open) => {
                setIconPopoverOpen(open);
                if (!open) setIconSearch("");
              }}
              modal={true}
            >
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  size="icon-sm"
                  className="h-8 w-8 p-0"
                  title={t("common:modals.createProject.pickIcon")}
                >
                  <SelectedIcon className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-64 p-2" align="start">
                <div className="space-y-2">
                  <Input
                    value={iconSearch}
                    onChange={(e) => setIconSearch(e.target.value)}
                    placeholder={t("common:modals.createProject.searchIcons")}
                    className="h-8 text-xs"
                  />
                  <div className="max-h-[280px] overflow-y-auto pr-1">
                    <div className="grid grid-cols-6 gap-1.5">
                      {filteredIcons.map(([iconName, Icon]) => {
                        const isSelected = selectedIcon === iconName;
                        return (
                          <Button
                            key={iconName}
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedIcon(iconName);
                              setIconPopoverOpen(false);
                              setIconSearch("");
                            }}
                            className={cn(
                              "h-10 items-center justify-center rounded-md p-0",
                              isSelected &&
                                "bg-sidebar-accent text-sidebar-accent-foreground",
                            )}
                            title={iconName}
                          >
                            <Icon className="h-4 w-4" />
                          </Button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </PopoverContent>
            </Popover>

            <Input
              unstyled
              value={name}
              onChange={handleNameChange}
              autoFocus
              placeholder={t("common:modals.createProject.projectName")}
              className="w-full [&_[data-slot=input]]:h-auto [&_[data-slot=input]]:px-0 [&_[data-slot=input]]:py-2 [&_[data-slot=input]]:text-2xl [&_[data-slot=input]]:leading-tight [&_[data-slot=input]]:font-semibold [&_[data-slot=input]]:tracking-tight [&_[data-slot=input]]:text-foreground [&_[data-slot=input]]:placeholder:text-muted-foreground [&_[data-slot=input]]:outline-none"
              required
            />

            <label htmlFor="project-local-path" className="block space-y-1.5">
              <span className="flex items-center gap-1.5 text-sm font-medium">
                <FolderOpen className="size-3.5" />
                Local project folder
              </span>
              <div className="flex items-center gap-2">
                <Input
                  id="project-local-path"
                  value={localPath}
                  onChange={(event) => setLocalPath(event.target.value)}
                  placeholder="/home/you/Projects/your-repository"
                  required
                  className="min-w-0 flex-1"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void handlePickFolder()}
                  disabled={isPickingFolder}
                >
                  {isPickingFolder ? "Opening…" : "Browse"}
                </Button>
              </div>
              <span className="block text-xs text-muted-foreground">
                Agents will use this folder as the project working directory.
              </span>
            </label>

            <label htmlFor="project-description" className="block space-y-1.5">
              <span className="text-sm font-medium">
                Description{" "}
                <span className="font-normal text-muted-foreground">
                  (optional)
                </span>
              </span>
              <Textarea
                id="project-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="What is this project about?"
                className="min-h-20"
              />
            </label>
          </div>

          <div className="space-y-3 px-3">
            <div className="flex items-center gap-3 p-3 rounded-xl bg-muted/50 border border-border">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-muted-foreground">
                  {t("common:modals.createProject.keyLabel")}
                </span>
                <Input
                  id="project-key"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value)}
                  placeholder="PRO"
                  maxLength={8}
                  className="w-20 h-8 text-center font-semibold text-sm bg-background border-border rounded-lg transition-colors duration-150"
                  required
                />
              </div>
              <div className="flex-1 text-xs text-muted-foreground opacity-80">
                {t("common:modals.createProject.keyHint", {
                  example: slug || "ABC",
                })}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              onClick={handleClose}
              variant="outline"
              size="sm"
              className="border-border text-foreground hover:bg-accent"
            >
              {t("common:actions.cancel")}
            </Button>
            <Button
              type="submit"
              disabled={!name.trim() || !slug.trim() || !localPath.trim()}
              size="sm"
              className="bg-primary hover:bg-primary/90  disabled:opacity-50"
            >
              {t("common:modals.createProject.createButton")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default CreateProjectModal;

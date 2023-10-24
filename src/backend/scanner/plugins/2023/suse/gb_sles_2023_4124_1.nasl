# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4124.1");
  script_cve_id("CVE-2022-41723", "CVE-2023-25173");
  script_tag(name:"creation_date", value:"2023-10-20 04:21:45 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-10-20 05:06:03 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 16:56:00 +0000 (Fri, 24 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4124-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234124-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'helm' package(s) announced via the SUSE-SU-2023:4124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for helm fixes the following issues:
helm was updated to version 3.13.1:

Fixing precedence issue with the import of values.
Add missing with clause to release gh action FIX Default ServiceAccount yaml fix(registry): unswallow error remove useless print during prepareUpgrade fix(registry): address anonymous pull issue Fix missing run statement on release action Write latest version to get.helm.sh bucket Increased release information key name max length.

helm was updated to version 3.13.0 (bsc#1215588):

Fix leaking goroutines in Install Update Helm to use k8s 1.28.2 libraries make the dependabot k8s.io group explicit use dependabot's group support for k8s.io dependencies doc:Executing helm rollback release 0 will roll back to the
 previous release Use labels instead of selectorLabels for pod labels fix(helm): fix GetPodLogs, the hooks should be sorted before
 get the logs of each hook chore: HTTPGetter add default timeout Avoid nil dereference if passing a nil resolver Add required changes after merge Fix #3352, add support for --ignore-not-found just like kubectl
 delete Fix helm may identify achieve of the application/x-gzip as
 application/vnd.ms-fontobject Restore helm get metadata command Revert 'Add helm get metadata command'
test: replace ensure.TempDir with t.TempDir use json api url + report curl/wget error on fail Added error in case try to supply custom label with name of
 system label during install/upgrade fix(main): fix basic auth for helm pull or push cmd: support generating index in JSON format repo: detect JSON and unmarshal efficiently Tweaking new dry-run internal handling bump kubernetes modules to v0.27.3 Remove warning for template directory not found.
Added tests for created OCI annotation time format Add created OCI annotation Fix multiple bugs in values handling chore: fix a typo in manager.go add GetRegistryClient method oci: add tests for plain HTTP and insecure HTTPS registries oci: Add flag --plain-http to enable working with HTTP
 registries docs: add an example for using the upgrade command with
 existing values Replace fmt.Fprintf with fmt.Fprint in get_metadata.go Replace fmt.Fprintln with fmt.Fprintf in get_metadata.go update kubernetes dependencies from v0.27.0 to v0.27.1 Add ClientOptResolver to test util file Check that missing keys are still handled in tpl tests: change crd golden file to match after #11870 Adding details on the Factory interface update autoscaling/v2beta1 to autoscaling/v2 in skeleton chart feat(helm): add ability for --dry-run to do lookup functions
 When a helm command is run with the --dry-run flag, it will try
 to connect to the cluster to be able to render lookup
 functions. Closes #8137 bugfix:(#11391) helm lint infinite loop when malformed
 template object pkg/engine: fix nil-dereference pkg/chartutil: fix nil-dereference pkg/action: fix nil-dereference full source path when output-dir is not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'helm' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Package Hub 15.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.13.1~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-bash-completion", rpm:"helm-bash-completion~3.13.1~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-debuginfo", rpm:"helm-debuginfo~3.13.1~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-zsh-completion", rpm:"helm-zsh-completion~3.13.1~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853036");
  script_version("2020-02-14T06:25:11+0000");
  script_cve_id("CVE-2019-3695", "CVE-2019-3696");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-02-14 06:25:11 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-13 04:00:30 +0000 (Thu, 13 Feb 2020)");
  script_name("openSUSE: Security Advisory for pcp (openSUSE-SU-2020:0213-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcp'
  package(s) announced via the openSUSE-SU-2020:0213-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcp fixes the following issues:

  Security issue fixed:

  - CVE-2019-3695: Fixed a local privilege escalation of the pcp user during
  package update (bsc#1152763).

  Non-security issue fixed:

  - Fixed an dependency issue with pcp2csv (bsc#1129991).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-213=1");

  script_tag(name:"affected", value:"'pcp' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libpcp-devel", rpm:"libpcp-devel~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp3", rpm:"libpcp3~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp3-debuginfo", rpm:"libpcp3-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_gui2", rpm:"libpcp_gui2~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_gui2-debuginfo", rpm:"libpcp_gui2-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_import1", rpm:"libpcp_import1~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_import1-debuginfo", rpm:"libpcp_import1-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_mmv1", rpm:"libpcp_mmv1~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_mmv1-debuginfo", rpm:"libpcp_mmv1-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_trace2", rpm:"libpcp_trace2~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_trace2-debuginfo", rpm:"libpcp_trace2-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_web1", rpm:"libpcp_web1~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_web1-debuginfo", rpm:"libpcp_web1-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp", rpm:"pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-conf", rpm:"pcp-conf~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-debuginfo", rpm:"pcp-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-debugsource", rpm:"pcp-debugsource~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-devel", rpm:"pcp-devel~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-devel-debuginfo", rpm:"pcp-devel-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2elasticsearch", rpm:"pcp-export-pcp2elasticsearch~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2graphite", rpm:"pcp-export-pcp2graphite~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2influxdb", rpm:"pcp-export-pcp2influxdb~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2json", rpm:"pcp-export-pcp2json~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2spark", rpm:"pcp-export-pcp2spark~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2xml", rpm:"pcp-export-pcp2xml~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-pcp2zabbix", rpm:"pcp-export-pcp2zabbix~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-zabbix-agent", rpm:"pcp-export-zabbix-agent~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-export-zabbix-agent-debuginfo", rpm:"pcp-export-zabbix-agent-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-gui", rpm:"pcp-gui~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-gui-debuginfo", rpm:"pcp-gui-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-collectl2pcp", rpm:"pcp-import-collectl2pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-collectl2pcp-debuginfo", rpm:"pcp-import-collectl2pcp-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-ganglia2pcp", rpm:"pcp-import-ganglia2pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-iostat2pcp", rpm:"pcp-import-iostat2pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-mrtg2pcp", rpm:"pcp-import-mrtg2pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-sar2pcp", rpm:"pcp-import-sar2pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-manager", rpm:"pcp-manager~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-manager-debuginfo", rpm:"pcp-manager-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-activemq", rpm:"pcp-pmda-activemq~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-apache", rpm:"pcp-pmda-apache~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-apache-debuginfo", rpm:"pcp-pmda-apache-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bash", rpm:"pcp-pmda-bash~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bash-debuginfo", rpm:"pcp-pmda-bash-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bind2", rpm:"pcp-pmda-bind2~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-bonding", rpm:"pcp-pmda-bonding~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cifs", rpm:"pcp-pmda-cifs~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cifs-debuginfo", rpm:"pcp-pmda-cifs-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cisco", rpm:"pcp-pmda-cisco~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-cisco-debuginfo", rpm:"pcp-pmda-cisco-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-dbping", rpm:"pcp-pmda-dbping~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-dm", rpm:"pcp-pmda-dm~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-dm-debuginfo", rpm:"pcp-pmda-dm-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-docker", rpm:"pcp-pmda-docker~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-docker-debuginfo", rpm:"pcp-pmda-docker-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-ds389", rpm:"pcp-pmda-ds389~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-ds389log", rpm:"pcp-pmda-ds389log~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-elasticsearch", rpm:"pcp-pmda-elasticsearch~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gfs2", rpm:"pcp-pmda-gfs2~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gfs2-debuginfo", rpm:"pcp-pmda-gfs2-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gluster", rpm:"pcp-pmda-gluster~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gpfs", rpm:"pcp-pmda-gpfs~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-gpsd", rpm:"pcp-pmda-gpsd~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-haproxy", rpm:"pcp-pmda-haproxy~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-infiniband", rpm:"pcp-pmda-infiniband~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-infiniband-debuginfo", rpm:"pcp-pmda-infiniband-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-json", rpm:"pcp-pmda-json~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lmsensors", rpm:"pcp-pmda-lmsensors~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-logger", rpm:"pcp-pmda-logger~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-logger-debuginfo", rpm:"pcp-pmda-logger-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lustre", rpm:"pcp-pmda-lustre~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lustrecomm", rpm:"pcp-pmda-lustrecomm~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-lustrecomm-debuginfo", rpm:"pcp-pmda-lustrecomm-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mailq", rpm:"pcp-pmda-mailq~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mailq-debuginfo", rpm:"pcp-pmda-mailq-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-memcache", rpm:"pcp-pmda-memcache~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mic", rpm:"pcp-pmda-mic~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mounts", rpm:"pcp-pmda-mounts~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mounts-debuginfo", rpm:"pcp-pmda-mounts-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-mysql", rpm:"pcp-pmda-mysql~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-named", rpm:"pcp-pmda-named~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-netfilter", rpm:"pcp-pmda-netfilter~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-news", rpm:"pcp-pmda-news~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nfsclient", rpm:"pcp-pmda-nfsclient~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nginx", rpm:"pcp-pmda-nginx~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nvidia-gpu", rpm:"pcp-pmda-nvidia-gpu~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-nvidia-gpu-debuginfo", rpm:"pcp-pmda-nvidia-gpu-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-oracle", rpm:"pcp-pmda-oracle~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-papi", rpm:"pcp-pmda-papi~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-papi-debuginfo", rpm:"pcp-pmda-papi-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-pdns", rpm:"pcp-pmda-pdns~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-perfevent", rpm:"pcp-pmda-perfevent~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-perfevent-debuginfo", rpm:"pcp-pmda-perfevent-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-postfix", rpm:"pcp-pmda-postfix~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-prometheus", rpm:"pcp-pmda-prometheus~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-redis", rpm:"pcp-pmda-redis~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-roomtemp", rpm:"pcp-pmda-roomtemp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-roomtemp-debuginfo", rpm:"pcp-pmda-roomtemp-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-rpm", rpm:"pcp-pmda-rpm~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-rpm-debuginfo", rpm:"pcp-pmda-rpm-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-rsyslog", rpm:"pcp-pmda-rsyslog~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-samba", rpm:"pcp-pmda-samba~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-sendmail", rpm:"pcp-pmda-sendmail~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-sendmail-debuginfo", rpm:"pcp-pmda-sendmail-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-shping", rpm:"pcp-pmda-shping~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-shping-debuginfo", rpm:"pcp-pmda-shping-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-slurm", rpm:"pcp-pmda-slurm~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-smart", rpm:"pcp-pmda-smart~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-smart-debuginfo", rpm:"pcp-pmda-smart-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-snmp", rpm:"pcp-pmda-snmp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-summary", rpm:"pcp-pmda-summary~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-summary-debuginfo", rpm:"pcp-pmda-summary-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-systemd", rpm:"pcp-pmda-systemd~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-systemd-debuginfo", rpm:"pcp-pmda-systemd-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-trace", rpm:"pcp-pmda-trace~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-trace-debuginfo", rpm:"pcp-pmda-trace-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-unbound", rpm:"pcp-pmda-unbound~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-vmware", rpm:"pcp-pmda-vmware~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-weblog", rpm:"pcp-pmda-weblog~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-weblog-debuginfo", rpm:"pcp-pmda-weblog-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-zimbra", rpm:"pcp-pmda-zimbra~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-pmda-zswap", rpm:"pcp-pmda-zswap~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-system-tools", rpm:"pcp-system-tools~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-system-tools-debuginfo", rpm:"pcp-system-tools-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-testsuite", rpm:"pcp-testsuite~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-testsuite-debuginfo", rpm:"pcp-testsuite-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-webapi", rpm:"pcp-webapi~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-webapi-debuginfo", rpm:"pcp-webapi-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-zeroconf", rpm:"pcp-zeroconf~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport", rpm:"perl-PCP-LogImport~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport-debuginfo", rpm:"perl-PCP-LogImport-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogSummary", rpm:"perl-PCP-LogSummary~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV", rpm:"perl-PCP-MMV~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV-debuginfo", rpm:"perl-PCP-MMV-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA", rpm:"perl-PCP-PMDA~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA-debuginfo", rpm:"perl-PCP-PMDA-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pcp", rpm:"python3-pcp~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pcp-debuginfo", rpm:"python3-pcp-debuginfo~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-doc", rpm:"pcp-doc~4.3.1~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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

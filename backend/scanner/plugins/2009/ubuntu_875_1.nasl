# OpenVAS Vulnerability Test
# $Id: ubuntu_875_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_875_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-875-1 (redhat-cluster-suite)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  ccs                             1.20060222-0ubuntu6.3
  cman                            1.20060222-0ubuntu6.3
  fence                           1.20060222-0ubuntu6.3
  libcman1                        1.20060222-0ubuntu6.3
  rgmanager                       1.20060222-0ubuntu6.3

Ubuntu 8.04 LTS:
  cman                            2.20080227-0ubuntu1.3
  gfs2-tools                      2.20080227-0ubuntu1.3
  rgmanager                       2.20080227-0ubuntu1.3

Ubuntu 8.10:
  cman                            2.20080826-0ubuntu1.3
  gfs2-tools                      2.20080826-0ubuntu1.3
  rgmanager                       2.20080826-0ubuntu1.3

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-875-1";

tag_insight = "Multiple insecure temporary file handling vulnerabilities were discovered
in Red Hat Cluster. A local attacker could exploit these to overwrite
arbitrary local files via symlinks. (CVE-2008-4192, CVE-2008-4579,
CVE-2008-4580, CVE-2008-6552)

It was discovered that CMAN did not properly handle malformed configuration
files. An attacker could cause a denial of service (via CPU consumption and
memory corruption) in a node if the attacker were able to modify the
cluster configuration for the node. (CVE-2008-6560)";
tag_summary = "The remote host is missing an update to redhat-cluster-suite
announced via advisory USN-875-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307664");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_cve_id("CVE-2008-4192", "CVE-2008-4579", "CVE-2008-4580", "CVE-2008-6552", "CVE-2008-6560");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Ubuntu USN-875-1 (redhat-cluster-suite)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-875-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"redhat-cluster-suite", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"redhat-cluster-suite-source", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ccs", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cman", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fence-gnbd", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fence", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gfs-tools", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-client", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-server", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gulm", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libccs-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm1", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgulm-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgulm1", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagma1", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"magma-plugins", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"magma", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rgmanager", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman1", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libiddev-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagma-dev", ver:"1.20060222-0ubuntu6.3", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"redhat-cluster-suite", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"redhat-cluster-source", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cman", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gfs-tools", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gfs2-tools", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-client", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-server", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman-dev", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman2", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm-dev", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm2", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rgmanager", ver:"2.20080227-0ubuntu1.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"redhat-cluster-suite", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"redhat-cluster-source", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cman", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gfs-tools", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gfs2-tools", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-client", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnbd-server", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libccs-dev", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libccs3", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman-dev", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcman3", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm-dev", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlm3", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlmcontrol-dev", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdlmcontrol3", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfence-dev", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfence3", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rgmanager", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libccs-perl", ver:"2.20080826-0ubuntu1.3", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

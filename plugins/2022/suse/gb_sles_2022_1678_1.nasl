# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1678.1");
  script_cve_id("CVE-2020-25649", "CVE-2020-28491", "CVE-2020-36518");
  script_tag(name:"creation_date", value:"2022-05-17 04:28:29 +0000 (Tue, 17 May 2022)");
  script_version("2022-05-17T04:28:29+0000");
  script_tag(name:"last_modification", value:"2022-05-19 09:49:33 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-18 19:52:00 +0000 (Fri, 18 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1678-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221678-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-annotations, jackson-bom, jackson-core, jackson-databind, jackson-dataformats-binary' package(s) announced via the SUSE-SU-2022:1678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jackson-databind, jackson-dataformats-binary,
jackson-annotations, jackson-bom, jackson-core fixes the following issues:

Security issues fixed:

CVE-2020-36518: Fixed a Java stack overflow exception and denial of
 service via a large depth of nested objects in jackson-databind.
 (bsc#1197132)

CVE-2020-25649: Fixed an insecure entity expansion in jackson-databind
 which was vulnerable to XML external entity (XXE). (bsc#1177616)

CVE-2020-28491: Fixed a bug which could cause
 `java.lang.OutOfMemoryError` exception in jackson-dataformats-binary.
 (bsc#1182481)

Non security fixes:

jackson-annotations - update from version 2.10.2 to version 2.13.0:

 + Build with source/target levels 8
 + Add 'mvnw' wrapper
 + 'JsonSubType.Type' should accept array of names
 + Jackson version alignment with Gradle 6
 + Add '@JsonIncludeProperties'
 + Add '@JsonTypeInfo(use=DEDUCTION)'
 + Ability to use '@JsonAnyGetter' on fields
 + Add '@JsonKey' annotation
 + Allow repeated calls to 'SimpleObjectIdResolver.bindItem()' for same
 mapping
 + Add 'namespace' property for '@JsonProperty' (for XML module)
 + Add target 'ElementType.ANNOTATION_TYPE' for '@JsonEnumDefaultValue'
 + 'JsonPattern.Value.pattern' retained as '', never (accidentally)
 exposed as 'null'
 + Rewrite to use `ant` for building in order to be able to use it in
 packages that have to be built before maven

jackson-bom - update from version 2.10.2 to version 2.13.0:

 + Configure moditect plugin with '11'
 + jackson-bom manages the version of 'junit:junit'
 + Drop 'jackson-datatype-hibernate3' (support for Hibernate 3.x
 datatypes)
 + Removed 'jakarta' classifier variants of JAXB/JSON-P/JAX-RS modules
 due to the addition of new Jakarta artifacts (Jakarta-JSONP,
 Jakarta-xmlbind-annotations, Jakarta-rs-providers)
 + Add version for 'jackson-datatype-jakarta-jsonp' module (introduced
 after 2.12.2)
 + Add (beta) version for 'jackson-dataformat-toml'
 + Jakarta 9 artifact versions are missing from jackson-bom
 + Add default settings for 'gradle-module-metadata-maven-plugin'
 (gradle metadata)
 + Add default settings for 'build-helper-maven-plugin'
 + Drop 'jackson-module-scala_2.10' entry (not released for Jackson 2.12
 or later)
 + Add override for 'version.plugin.bundle' (for 5.1.1) to help build on
 JDK 15+
 + Add missing version for jackson-datatype-eclipse-collections

jackson-core - update from version 2.10.2 to version 2.13.0:

 + Build with source and target levels 8
 + Misleading exception for input source when processing byte buffer
 with start offset
 + Escape contents of source document snippet for
 'JsonLocation._appendSourceDesc()'
 + Add 'StreamWriteException' type to eventually replace
 'JsonGenerationException'
 + Replace 'getCurrentLocation()'/'getTokenLocation()' with
 'currentLocation()'/'currentTokenLocation()' in 'JsonParser'
 + Replace 'JsonGenerator.writeObject()' (and related) with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'jackson-annotations, jackson-bom, jackson-core, jackson-databind, jackson-dataformats-binary' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for SUSE Manager Server 4.3, SUSE Linux Enterprise Realtime Extension 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations", rpm:"jackson-annotations~2.13.0~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations-javadoc", rpm:"jackson-annotations-javadoc~2.13.0~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core", rpm:"jackson-core~2.13.0~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core-javadoc", rpm:"jackson-core-javadoc~2.13.0~150200.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.13.0~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind-javadoc", rpm:"jackson-databind-javadoc~2.13.0~150200.3.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-cbor", rpm:"jackson-dataformat-cbor~2.13.0~150200.3.3.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations", rpm:"jackson-annotations~2.13.0~150200.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core", rpm:"jackson-core~2.13.0~150200.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.13.0~150200.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-cbor", rpm:"jackson-dataformat-cbor~2.13.0~150200.3.3.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations", rpm:"jackson-annotations~2.13.0~150200.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core", rpm:"jackson-core~2.13.0~150200.3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.13.0~150200.3.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-cbor", rpm:"jackson-dataformat-cbor~2.13.0~150200.3.3.3", rls:"SLES15.0SP2"))) {
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

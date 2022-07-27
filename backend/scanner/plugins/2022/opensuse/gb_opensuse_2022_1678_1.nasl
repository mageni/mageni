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
  script_oid("1.3.6.1.4.1.25623.1.0.854617");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2020-25649", "CVE-2020-28491", "CVE-2020-36518");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:05:43 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for jackson-databind, (SUSE-SU-2022:1678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1678-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WTX6HAJ7KVGVZQ6APMA35RM7R7BKVSMB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jackson-databind, '
  package(s) announced via the SUSE-SU-2022:1678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jackson-databind, jackson-dataformats-binary,
     jackson-annotations, jackson-bom, jackson-core fixes the following issues:
  Security issues fixed:

  - CVE-2020-36518: Fixed a Java stack overflow exception and denial of
       service via a large depth of nested objects in jackson-databind.
       (bsc#1197132)

  - CVE-2020-25649: Fixed an insecure entity expansion in jackson-databind
       which was vulnerable to XML external entity (XXE). (bsc#1177616)

  - CVE-2020-28491: Fixed a bug which could cause
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
  + Configure moditect plugin with ' jvmVersion 11 /jvmVersion '
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
        + Add override for 'version.plugin.bundle' (for 5.1.1) ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'jackson-databind, ' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations", rpm:"jackson-annotations~2.13.0~150200.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations-javadoc", rpm:"jackson-annotations-javadoc~2.13.0~150200.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-bom", rpm:"jackson-bom~2.13.0~150200.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core", rpm:"jackson-core~2.13.0~150200.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core-javadoc", rpm:"jackson-core-javadoc~2.13.0~150200.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.13.0~150200.3.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind-javadoc", rpm:"jackson-databind-javadoc~2.13.0~150200.3.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-cbor", rpm:"jackson-dataformat-cbor~2.13.0~150200.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-smile", rpm:"jackson-dataformat-smile~2.13.0~150200.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformats-binary", rpm:"jackson-dataformats-binary~2.13.0~150200.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformats-binary-javadoc", rpm:"jackson-dataformats-binary-javadoc~2.13.0~150200.3.3.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations", rpm:"jackson-annotations~2.13.0~150200.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-annotations-javadoc", rpm:"jackson-annotations-javadoc~2.13.0~150200.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-bom", rpm:"jackson-bom~2.13.0~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core", rpm:"jackson-core~2.13.0~150200.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-core-javadoc", rpm:"jackson-core-javadoc~2.13.0~150200.3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind", rpm:"jackson-databind~2.13.0~150200.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-databind-javadoc", rpm:"jackson-databind-javadoc~2.13.0~150200.3.9.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-cbor", rpm:"jackson-dataformat-cbor~2.13.0~150200.3.3.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformat-smile", rpm:"jackson-dataformat-smile~2.13.0~150200.3.3.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformats-binary", rpm:"jackson-dataformats-binary~2.13.0~150200.3.3.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jackson-dataformats-binary-javadoc", rpm:"jackson-dataformats-binary-javadoc~2.13.0~150200.3.3.3", rls:"openSUSELeap15.3"))) {
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
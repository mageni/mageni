###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0677_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox, openSUSE-SU-2015:0677-1 (MozillaFirefox,)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850647");
  script_version("$Revision: 12381 $");
  script_cve_id("CVE-2015-0799", "CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803",
                "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807",
                "CVE-2015-0808", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813",
                "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-04-09 07:05:52 +0200 (Thu, 09 Apr 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox, openSUSE-SU-2015:0677-1 (MozillaFirefox, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox and Thunderbird were updated to fix several important
  vulnerabilities.

  Mozilla Firefox was updated to 37.0.1. Mozilla Thunderbird was updated to
  31.6.0. mozilla-nspr was updated to 4.10.8 as a dependency.

  The following vulnerabilities were fixed in Mozilla Firefox:

  * Miscellaneous memory safety hazards (MFSA
  2015-30/CVE-2015-0814/CVE-2015-0815 boo#925392)

  * Use-after-free when using the Fluendo MP3 GStreamer plugin (MFSA
  2015-31/CVE-2015-0813 bmo#1106596 boo#925393)

  * Add-on lightweight theme installation approval bypassed through MITM
  attack (MFSA 2015-32/CVE-2015-0812 bmo#1128126 boo#925394)

  * resource:// documents can load privileged pages (MFSA
  2015-33/CVE-2015-0816 bmo#1144991 boo#925395)

  * Out of bounds read in QCMS library (MFSA-2015-34/CVE-2015-0811
  bmo#1132468 boo#925396)

  * Incorrect memory management for simple-type arrays in WebRTC
  (MFSA-2015-36/CVE-2015-0808 bmo#1109552 boo#925397)

  * CORS requests should not follow 30x redirections after preflight
  (MFSA-2015-37/CVE-2015-0807 bmo#1111834 boo#925398)

  * Memory corruption crashes in Off Main Thread Compositing
  (MFSA-2015-38/CVE-2015-0805/CVE-2015-0806 bmo#1135511 bmo#1099437
  boo#925399)

  * Use-after-free due to type confusion flaws
  (MFSA-2015-39/CVE-2015-0803/CVE-2015-0804 (mo#1134560 boo#925400)

  * Same-origin bypass through anchor navigation (MFSA-2015-40/CVE-2015-0801
  bmo#1146339 boo#925401)

  * Windows can retain access to privileged content on navigation to
  unprivileged pages (MFSA-2015-42/CVE-2015-0802 bmo#1124898 boo#925402)

  The following vulnerability was fixed in functionality that was not
  released as an update to openSUSE:

  * Certificate verification could be bypassed through the HTTP/2 Alt-Svc
  header (MFSA 2015-44/CVE-2015-0799 bmo#1148328 bnc#926166)

  The functionality added in 37.0 and thus removed in 37.0.1 was:

  * Opportunistically encrypt HTTP traffic where the server supports HTTP/2
  AltSvc

  The following functionality was added or updated in Mozilla Firefox:

  * Heartbeat user rating system

  * Yandex set as default search provider for the Turkish locale

  * Bing search now uses HTTPS for secure searching

  * Improved protection against site impersonation via OneCRL centralized
  certificate revocation

  * some more behaviour changes for TLS

  The following vulnerabilities were fixed in Mozilla Thunderbird:

  * Miscellaneous memory safety hazards (MFSA
  2015-30/CVE-2015-0814/CVE-2015-0815 boo#925392)

  * Use-after-free when using the Fluendo MP3 GStreamer plugin (MFSA
  2015-31/CVE-2015-0813 bmo#1106596 boo#925393)
   ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MozillaFirefox, on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~37.0.1~68.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~31.6.0~70.50.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.10.8~22.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

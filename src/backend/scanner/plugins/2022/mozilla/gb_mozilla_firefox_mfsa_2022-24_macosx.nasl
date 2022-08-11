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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821170");
  script_version("2022-07-14T06:41:19+0000");
  script_cve_id("CVE-2022-34470", "CVE-2022-34468", "CVE-2022-34482", "CVE-2022-34483",
                "CVE-2022-34476", "CVE-2022-34481", "CVE-2022-34474", "CVE-2022-34471",
                "CVE-2022-34472", "CVE-2022-2200", "CVE-2022-34480", "CVE-2022-34477",
                "CVE-2022-34475", "CVE-2022-34473", "CVE-2022-34484", "CVE-2022-34485");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-14 06:41:19 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-07 23:27:12 +0530 (Thu, 07 Jul 2022)");
  script_name("Mozilla Firefox Security Updates(mfsa2022-24) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A popup window could be resized in a way to overlay the address bar with web content.

  - Use-after-free in nsSHistory.

  - CSP sandbox header without `allow-scripts` can be bypassed via retargeted javascript: URI.

  - Drag and drop of malicious image could have led to malicious executable and potential code execution.

  - ASN.1 parser could have been tricked into accepting malformed ASN.1.

  - Potential integer overflow in ReplaceElementsAt.

  - Sandboxed iframes could redirect to external schemes.

  - TLS certificate errors on HSTS-protected domains could be bypassed by the user on Firefox for Android.

  - Compromised server could trick a browser into an addon downgrade.

  - Unavailable PAC file resulted in OCSP requests being blocked.

  - Microsoft protocols can be attacked if a user accepts a prompt.

  - Undesired attributes could be set as part of prototype pollution.

  - Free of uninitialized pointer in lg_init.

  - MediaError message property leaked information on cross-origin same-site pages.

  - HTML Sanitizer could have been bypassed via same-origin script via use tags.

  - HTML Sanitizer could have been bypassed via use tags.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  102 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 102
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-24");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102", install_path:path);
  security_message(data:report);
  exit(0);
}

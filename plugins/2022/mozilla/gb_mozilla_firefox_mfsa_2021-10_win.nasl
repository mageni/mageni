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
  script_oid("1.3.6.1.4.1.25623.1.0.821226");
  script_cve_id("CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23983", "CVE-2021-23984",
                "CVE-2021-23985", "CVE-2021-23986", "CVE-2021-23987", "CVE-2021-23988",
                "CVE-2021-29951", "CVE-2021-29955");
  script_tag(name:"creation_date", value:"2022-05-10 11:10:02 +0530 (Tue, 10 May 2022)");
  script_version("2022-05-19T11:50:09+0000");
  script_tag(name:"last_modification", value:"2022-05-20 09:52:18 +0000 (Fri, 20 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 12:15:00 +0000 (Thu, 24 Jun 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-10) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_xref(name:"Advisory-ID", value:"MFSA2021-10");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-10/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1513519%2C1683439%2C1690169%2C1690718");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1684994%2C1686653");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1659129");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1677046");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1690062");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1692623");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1692684");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1692832");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1692972");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1693664");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-29955: Transient Execution Vulnerability allowed leaking arbitrary memory address
A transient execution vulnerability, named Floating Point Value Injection (FPVI) allowed an attacker to leak arbitrary memory addresses and may have also enabled JIT type confusion attacks. (A related vulnerability, Speculative Code Store Bypass (SCSB), did not affect Firefox.)

CVE-2021-23981: Texture upload into an unbound backing buffer resulted in an out-of-bound read
A texture upload of a Pixel Buffer Object could have confused the WebGL code to skip binding the buffer used to unpack it, resulting in memory corruption and a potentially exploitable information leak or crash.

CVE-2021-29951: Mozilla Maintenance Service could have been started or stopped by domain users
The Mozilla Maintenance Service granted SERVICE_START access to BUILTIN<pipe>Users which, in a domain network, grants normal remote users access to start or stop the service. This could be used to prevent the browser update service from operating (if an attacker spammed the 'Stop' command), but also exposed attack surface in the maintenance service.Note: This issue only affected Windows operating systems older than Win 10 build 1709. Other operating systems are unaffected.

CVE-2021-23982: Internal network hosts could have been probed by a malicious webpage
Using techniques that built on the slipstream research, a malicious webpage could have scanned both an internal network's hosts as well as services running on the user's local machine utilizing WebRTC connections.

CVE-2021-23983: Transitions for invalid ::marker properties resulted in memory corruption
By causing a transition on a parent node by removing a CSS rule, an invalid property for a marker could have been applied, resulting in memory corruption and a potentially exploitable crash.

CVE-2021-23984: Malicious extensions could have spoofed popup information
A malicious extension could have opened a popup window lacking an address bar. The title of the popup lacking an address bar should not be fully controllable, but in this situation was. This could have been used to spoof a website and attempt to trick the user into providing credentials.

CVE-2021-23985: Devtools remote debugging feature could have been enabled without indication to the user
If an attacker is able to alter specific about:config values (for example malware running on the user's computer), the Devtools remote debugging feature could have been enabled in a way that was unnoticable to the user. This would have allowed a remote attacker (able to make a direct network connection to the victim) to monitor the user's browsing activity and (plaintext) network traffic. This was addressed by providing a visual cue when Devtools has an open network socket.

CVE-2021-23986: A malicious extension could have performed credential-less same origin policy violations
A malicious extension with the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 87.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "87")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "87", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

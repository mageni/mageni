# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.01");
  script_cve_id("CVE-2011-3079", "CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18502", "CVE-2018-18503", "CVE-2018-18504", "CVE-2018-18505", "CVE-2018-18506");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-15T10:47:05+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1499426%2C1480090%2C1472990%2C1514762%2C1501482%2C1505887%2C1508102%2C1508618%2C1511580%2C1493497%2C1510145%2C1516289%2C1506798%2C1512758");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1512450%2C1517542%2C1513201%2C1460619%2C1502871%2C1516738%2C1516514");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1087565");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1496413");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1497749");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1503393");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1509442");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510114");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-18500: Use-after-free parsing HTML5 stream
A use-after-free vulnerability can occur while parsing an HTML5 stream in concert with custom HTML elements. This results in the stream parser object being freed while still in use, leading to a potentially exploitable crash.

CVE-2018-18504: Memory corruption and out-of-bounds read of texture client buffer
A crash and out-of-bounds read can occur when the buffer of a texture client is freed while it is still in use during graphic operations. This results in a potentially exploitable crash and the possibility of reading from the memory of the freed buffers.

CVE-2018-18505: Privilege escalation through IPC channel messages
An earlier fix for an Inter-process Communication (IPC) vulnerability, CVE-2011-3079, added authentication to communication between IPC endpoints and server parents during IPC process creation. This authentication is insufficient for channels created after the IPC process is started, leading to the authentication not being correctly applied to later channels. This could allow for a sandbox escape through IPC channels due to lack of message validation in the listener process.

CVE-2018-18503: Memory corruption with Audio Buffer
When JavaScript is used to create and manipulate an audio buffer, a potentially exploitable crash may occur because of a compartment mismatch in some situations.

CVE-2018-18506: Proxy Auto-Configuration file can define localhost access to be proxied
When proxy auto-detection is enabled, if a web server serves a Proxy Auto-Configuration (PAC) file or if a PAC file is loaded locally, this PAC file can specify that requests to the localhost are to be sent through the proxy to another server. This behavior is disallowed by default when a proxy is manually configured, but when enabled could allow for attacks on services and tools that bind to the localhost for networked behavior if they are accessed through browsing.

CVE-2018-18502: Memory safety bugs fixed in Firefox 65
Mozilla developers and community members Arthur Iakab, Christoph Diehl, Christian Holler, Kalel, Emilio Cobos Alvarez, Cristina Coroiu, Noemi Erli, Natalia Csoregi, Julian Seward, Gary Kwong, Tyson Smith, Yaron Tausky, and Ronald Crane reported memory safety bugs present in Firefox 64. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code.

CVE-2018-18501: Memory safety bugs fixed in Firefox 65 and Firefox ESR 60.5
Mozilla developers and community members Alex Gaynor, Christoph Diehl, Steven Crane, Jason Kratzer, Gary Kwong, and Christian Holler reported memory safety bugs present in Firefox 64 and Firefox ESR 60.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 65.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "65", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

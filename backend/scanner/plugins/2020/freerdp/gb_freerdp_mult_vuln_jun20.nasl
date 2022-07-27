# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113703");
  script_version("2020-06-16T07:17:49+0000");
  script_tag(name:"last_modification", value:"2020-06-16 09:40:41 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-15 11:15:43 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11017", "CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11039", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11043", "CVE-2020-11085", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11089");

  script_name("FreeRDP < 2.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - By providing manipulated input a malicious client can
    create a double free condition and crash the server. (CVE-2020-11017)

  - Malicious clients could trigger out of bound reads
    causing memory allocation with random size. (CVE-2020-11018)

  - When running with logger set to 'WLOG_TRACE', a possible crash of application could occur
    due to a read of an invalid array index. Data could be printed as string to local terminal. (CVE-2020-11019)

  - When using /video redirection, a manipulated server can instruct the client
    to allocate a buffer with a smaller size than requested due to an integer overflow in size calculation.
    With later messages, the server can manipulate the client
    to write data out of bound to the previously allocated buffer. (CVE-2020-11038)

  - When using a manipulated server with USB redirection enabled,
    arbitrary memory can be read and written due to integer overflows in length checks. (CVE-2020-11039)

  - There is an out-of-bound data read from memory
    in clear_decompress_subcode_rlex, visualized on screen as color. (CVE-2020-11040)

  - An outside controlled array index is used unchecked for data used as configuration for sound backend.
    The most likely outcome is a crash of the client instance followed by no or distorted sound or a session disconnect.
    If a user cannot upgrade to the patched version, a workaround is to disable sound for the session. (CVE-2020-11041)

  - There is an out-of-bounds read in rfx_process_message_tileset.
    Invalid data fed to RFX decoder results in garbage on screen (as colors). (CVE-2020-11043)

  - There is an out-of-bounds read in cliprdr_read_format_list.
    Clipboard format data read (by client or server) might read data out-of-bounds. (CVE-2020-11085)

  - There is an out-of-bound read in ntlm_read_ntlm_v2_client_challenge
    that reads up to 28 bytes out-of-bound to an internal structure. (CVE-2020-11086)

  - There is an out-of-bound read in ntlm_read_AuthenticateMessage. (CVE-2020-11087)

  - There is an out-of-bound read in ntlm_read_NegotiateMessage. (CVE-2020-11088)

  - There is an out-of-bound read in irp functions
    (parallel_process_irp_create, serial_process_irp_create, drive_process_irp_write,
    printer_process_irp_write, rdpei_recv_pdu, serial_process_irp_write). (CVE-2020-11089)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  read sensitive information, crash the application or gain control over the target system.");

  script_tag(name:"affected", value:"FreeRDP through version 2.0.0.");

  script_tag(name:"solution", value:"Update to version 2.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-q5c8-fm29-q57c");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8cvc-vcw7-6mfw");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-wvrr-2f4r-hjvh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-h25x-cqr6-fp6g");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mx9p-f6q8-mqwq");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-x4wq-m7c9-rjgr");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-w67c-26c4-2h9w");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5mr4-28w3-rc84");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-2j4w-v45m-95hf");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-fg8v-w34r-c974");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-84vj-g73m-chw7");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-xh4f-fh87-43hp");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-hfc7-c5gv-8c2h");

  exit(0);
}

CPE = "cpe:/a:freerdp_project:freerdp";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.1.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

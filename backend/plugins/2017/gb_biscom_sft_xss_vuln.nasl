##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_biscom_sft_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Biscom Secure File Transfer XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:biscom:secure_file_transfer';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140301");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-15 16:54:53 +0700 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-5241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Biscom Secure File Transfer XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_biscom_sft_detect.nasl");
  script_mandatory_keys("biscom_sft/installed");

  script_tag(name:"summary", value:"Biscom Secure File Transfer is prone to a cross-site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Workspaces component of Biscom Secure File Transfer (SFT) is vulnerable
to stored cross-site scripting in two fields. An attacker would need to have the ability to create a Workspace
and entice a victim to visit the malicious page in order to run malicious Javascript in the context of the
victim's browser. Since the victim is necessarily authenticated, this can allow the attacker to perform actions
on the Biscom Secure File Transfer instance on the victim's behalf.");

  script_tag(name:"affected", value:"Synology Photo Station before 5.1.1025.");

  script_tag(name:"solution", value:"Update to version 5.1.1025 or later.");

  script_xref(name:"URL", value:"https://community.rapid7.com/community/infosec/blog/2017/06/27/r7-2017-06-biscom-sftp-xss-cve-2017-5241");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.1.1025")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.1025");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

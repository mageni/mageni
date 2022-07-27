###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubnt_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Ubiquiti Networks EdgeRouter XSS Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106984");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-25 13:16:00 +0700 (Tue, 25 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ubiquiti Networks EdgeRouter XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ubnt_discovery_protocol_detect.nasl");
  script_mandatory_keys("ubnt_discovery_proto/detected", "ubnt_discovery_proto/short_model",
"ubnt_discovery_proto/firmware");

  script_tag(name:"summary", value:"Ubiquiti Networks EdgeRouter are prone to a cross-site
scripting vulnerability.");

  script_tag(name:"insight", value:"A reflected cross site scripting vulnerability was identified because of an
initialization error in '/files/index/'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Ubiquiti Networks EP-R6, ER-X, ER-X-SFP firmware version 1.9.1 and prior.");

  script_tag(name:"solution", value:"Update to firmware version 1.9.1.1 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170724-0_Ubiquiti_Networks_EdgeRouter_XSS_v10.txt");

  exit(0);
}

include("version_func.inc");

model = get_kb_item("ubnt_discovery_proto/short_model");
if (!model || (model != "EP-R6" && model != "ER-X" && model != "ER-X-SFP"))
  exit(0);

fw = get_kb_item("ubnt_discovery_proto/firmware");
if (!fw)
  exit(0);

vers = eregmatch(pattern: "\.v([0-9]\.[0-9]\.[0-9](\.[0-9]\.)?)", string: fw);
if (isnull(vers[1]))
  exit(0);

# strip the last dot if present
vers = eregmatch(pattern: "([0-9]\.[0-9]\.[0-9](\.[0-9])?)", string: vers[1]);
version = vers[1];

if (version_is_less(version: version, test_version: "1.9.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

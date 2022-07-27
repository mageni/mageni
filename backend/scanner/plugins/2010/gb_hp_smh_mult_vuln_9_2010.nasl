###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_9_2010.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# HP System Management Homepage Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:system_management_homepage";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100810");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_bugtraq_id(43269, 43208);
  script_cve_id("CVE-2010-3011", "CVE-2010-3009", "CVE-2010-3012");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("HP System Management Homepage Multiple Vulnerabilities");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43269");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43208");
  script_xref(name:"URL", value:"http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02512995&admit=109447626+1284637282234+28353475");
  script_xref(name:"URL", value:"https://www.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02475053");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"HP System Management Homepage is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"1. An HTTP response-splitting vulnerability.

  Attackers can leverage this issue to influence or misrepresent how web
  content is served, cached, or interpreted. This could aid in various
  attacks that try to entice client users into a false sense of trust.

  2. An unspecified remote information-disclosure vulnerability.

  Remote attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"HP System Management Homepage versions prior to 6.2 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version: version, test_version: "6.2.0.12")) {
    security_message(port:port);
    exit(0);
}

exit(99);
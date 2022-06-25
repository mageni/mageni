###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_splunk_mult_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Splunk Multiple vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:splunk:splunk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901152");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3322", "CVE-2010-3323");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Multiple vulnerabilities");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAFQ6");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");
  script_require_ports("Services/www", 8000);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
and gain privileges.");

  script_tag(name:"affected", value:"Splunk version 4.0.0 through 4.1.4");

  script_tag(name:"insight", value:"- XML parser is vulnerable to XXE (XML eXternal Entity) attacks, which
allows remote authenticated users to obtain sensitive information and gain privileges.

  - SPLUNKD_SESSION_KEY parameter is vulnerable to session hijacking.");

  script_tag(name:"solution", value:"Upgrade to Splunk version 4.1.5 or later.");

  script_tag(name:"summary", value:"This host is running Splunk and is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://www.splunk.com/download");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.0", test_version2:"4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

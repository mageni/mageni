###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_mailwise_mul_vuln_aug16.nasl 11835 2018-10-11 08:38:49Z mmartin $
#
# Cybozu Mailwise Multiple Vulnerabilities Aug-2016
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cybozu:mailwise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107163");
  script_version("$Revision: 11835 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 10:38:49 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-11 12:30:22 +0200 (Thu, 11 May 2017)");
  script_cve_id("CVE-2016-4842", "CVE-2016-4844", "CVE-2016-4843", "CVE-2016-4841");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Mailwise Multiple Vulnerabilities Aug-2016");
  script_tag(name:"summary", value:"This host is installed with Cybozu Mailwise
  and is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain information on when an email is read,
  conduct clickjacking attacks, obtain sensitive cookie information and inject arbitrary email headers.");
  script_tag(name:"affected", value:"Cybozu Mailwise before version 5.4.0.");
  script_tag(name:"solution", value:"Update to Cybozu Mailwise 5.4.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92460");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92461");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92462");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuMailWise/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port: Port)){
  exit(0);
}

if(version_is_less(version: Ver, test_version:"5.4.0")){
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"5.4.0");
  security_message(data:report, port: Port);
  exit(0);
}

exit (99);

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_cgi_info_disc_vuln_win.nasl 12358 2018-11-15 07:57:20Z cfischer $
#
# Python CGIHTTPServer Module Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801796");
  script_version("$Revision: 12358 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 08:57:20 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-1015");
  script_bugtraq_id(46541);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_name("Python CGIHTTPServer Module Information Disclosure Vulnerability");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("python6432/win/detected");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2254");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025489");
  script_xref(name:"URL", value:"http://hg.python.org/cpython/rev/c6c4398293bd/");
  script_xref(name:"URL", value:"http://svn.python.org/view?view=revision&revision=71303");

  script_tag(name:"insight", value:"The flaw is due to an error when handling 'is_cgi' method in
  'CGIHTTPServer.py' in the 'CGIHTTPServer module', which allows an attcker to
  supply a specially crafted request without the leading '/' character to the CGIHTTPServer.");

  script_tag(name:"summary", value:"This host is installed with Python and is prone to Information
  Disclosure vulnerability.");

  script_tag(name:"solution", value:"Source code patches are available, please see the references for
  more information.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain access to potentially
  sensitive information contained in arbitrary scripts by requesting cgi script
  without / in the beginning of URL.");

  script_tag(name:"affected", value:"Python version 2.5, 2.6, and 3.0.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pyVer = infos['version'];
pypath = infos['location'];

if(version_is_equal(version:pyVer, test_version:"2.5") ||
   version_is_equal(version:pyVer, test_version:"2.6") ||
   version_is_equal(version:pyVer, test_version:"3.0")){
  report = report_fixed_ver(installed_version:pyVer, fixed_version:"See references", install_path:pypath);
  security_message(data:report);
}

exit(0);
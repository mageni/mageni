###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_jabber_starttls_downgrade_vuln_win.nasl 55850 2016-11-28 15:48:43Z Nov$
#
# Cisco Jabber STARTTLS Downgrade Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:jabber";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809089");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2015-6409");
  script_bugtraq_id(79678);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-28 15:48:43 +0530 (Mon, 28 Nov 2016)");
  script_name("Cisco Jabber STARTTLS Downgrade Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Cisco
  Jabber and is prone to STARTTLS downgrade vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the client does not
  verify that an Extensible Messaging and Presence Protocol (XMPP) connection has
  been established with Transport Layer Security (TLS).");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerabilitywill allow an attacker to cause the client to establish a
  cleartext XMPP connection.");

  script_tag(name:"affected", value:"Cisco Jabber versions 10.6(2) before
  10.6(7), 11.1.x before 11.1(3), 11.5.x before 11.5(1) and 9.7(5) before
  9.7(7).");

  script_tag(name:"solution", value:"Upgrade to 10.6(7) or 11.1(3) or
  11.5(1) or 9.7(7) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151224-jab");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_jabber_detect_win.nasl");
  script_mandatory_keys("Cisco/Jabber/Win/Ver");
  script_xref(name:"URL", value:"http://www.cisco.com/web/products/voice/jabber.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jbVer = get_app_version(cpe:CPE)){
  exit(0);
}

#Removing Build from Version
jbVer = ereg_replace(string:jbVer, pattern:".[0-9][0-9]+", replace:"");
if(!jbVer){
  exit(0);
}

if(jbVer =~ "^(10|11|9)")
{
  if(version_in_range(version:jbVer, test_version:"10.6.2", test_version2:"10.6.6"))
  {
    VULN = TRUE;
    fix = "10.6.7";
  }

  else if(jbVer =~ "^11\.")
  {
    if(version_in_range(version:jbVer, test_version:"11.1", test_version2:"11.1.2"))
    {
      VULN = TRUE;
      fix = "11.1.3";
    }

    else if(version_is_equal(version:jbVer, test_version:"11.5"))
    {
      VULN = TRUE;
      fix = "11.5.1";
    }
  }

  else if(version_in_range(version:jbVer, test_version:"9.7.5", test_version2:"9.7.6"))
  {
    VULN = TRUE;
    fix = "9.7.7";
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:jbVer, fixed_version:fix);
    security_message(data:report);
    exit(0);
  }
}

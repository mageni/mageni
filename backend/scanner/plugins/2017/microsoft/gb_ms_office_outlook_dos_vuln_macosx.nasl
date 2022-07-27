###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_outlook_dos_vuln_macosx.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Microsoft Office Outlook Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811832");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2014-2730");
  script_bugtraq_id(78020);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-19 15:38:09 +0530 (Tue, 19 Sep 2017)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("Microsoft Office Outlook Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Microsoft Office Outlook
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the XML parser in Microsoft
  Office does not properly detect recursion during entity expansion.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to cause a denial of service (memory consumption and persistent
  application hang) via a crafted XML document.");

  script_tag(name:"affected", value:"Microsoft Outlook 2011 on Mac OS X");

  script_tag(name:"solution", value:"A workaround is to add a rule blocking
  XML DTD Entities ('<!ENTITY', case-insensitive) to your spam filter. Creating
  an Outlook rule to permanently delete messages containing '<!ENTITY' also
  mitigates the attack.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/531722/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^(14\.)")
{
  report = report_fixed_ver(installed_version: offVer, fixed_version: "Mitigation");
  security_message(data:report);
  exit(0);
}

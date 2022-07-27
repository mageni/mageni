##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oprofile_mult_vuln.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# OProfile Multiple Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802108");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2011-1760", "CVE-2011-2471", "CVE-2011-2472", "CVE-2011-2473");
  script_bugtraq_id(47652);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OProfile Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=700883");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/05/10/7");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/05/03/1");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=624212#19");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_oprofile_detect.nasl");
  script_mandatory_keys("OProfile/Ver");
  script_tag(name:"insight", value:"The flaws are due to an error,

  - while handling content of event argument, provided to oprofile profiling
    control utility (opcontrol).

  - while handling 'do_dump_data' function, allows local users to create or
    overwrite arbitrary files via a crafted --session-dir argument in
    conjunction with a symlink attack on the opd_pipe file.

  - in 'utils/opcontrol', allow local users to conduct eval injection attacks
    and gain privileges via shell meta characters in the several arguments.");
  script_tag(name:"summary", value:"This host is installed OProfile and is prone to multiple
  vulnerabilities.");
  script_tag(name:"solution", value:"Apply the  patch from the referenced advisory.
  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499233");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499234");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499235");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to run arbitrary commands with
  super-user privileges.");
  script_tag(name:"affected", value:"OProfile version 0.9.6 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=499232");
  exit(0);
}


include("version_func.inc");

opVer = get_kb_item("OProfile/Ver");
if(!opVer){
  exit(0);
}

if(version_is_less_equal(version:opVer, test_version:"0.9.6")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

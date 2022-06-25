###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_office_detect_macosx.nasl 10468 2018-07-09 13:54:40Z cfischer $
#
# Microsoft Office Version Detection (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802431");
  script_version("$Revision: 10468 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 15:54:40 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 10:50:16 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Version Detection (Mac OS X)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Office.

  The script logs in via ssh, and searches for Microsoft Office '.app' folder
  and queries the related 'Info.plist' file for string'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if(!get_kb_item("ssh/login/osx_name")){
  close(sock);
  exit(0);
}

# TODO: This NVT is currently only detecting and reporting the oldest available
# installation of Office, even if there is a newer installed in parallel...
foreach offVer (make_list("2008", "2011")){

  offVersion = chomp(ssh_cmd(socket:sock, cmd:"defaults read  /Applications/" +
               "Microsoft\ Office\ " + offVer +  "/Microsoft\ Document\ " +
               "Connection.app/Contents/Info CFBundleShortVersionString"));
  location =  "/Applications/Microsoft\ Office\ " + offVer +
              "/Microsoft\ Document\ Connection.app/Contents/Info.plist";
  concluded = offVersion;

  if(!strlen(offVersion) > 0 || "does not exist" >< offVersion){
    # nb: Reset to avoid that we're keeping the error message:
    # The domain/default pair of *snip* does not exist
    # in the offVersion variable which would cause a false detection below...
    offVersion = NULL;
    continue;
  } else {
    break;
  }
}

if(!offVersion){

  ## Excel.app, OneNote.app, PowerPoint.app, Outlook.app, Word.app comes after office 2016 installation on mac
  offname = chomp(ssh_cmd(socket:sock, cmd:"ls /Applications"));

  ver = eregmatch(pattern:'(Excel|OneNote|PowerPoint|Outlook|Word).app', string:offname);

  if(ver[0]){
    offname = chomp(ssh_cmd(socket:sock, cmd:"defaults read  /Applications/" +
                   "Microsoft\ " + ver[0] + "/Contents/Info CFBundleGetInfoString"));

   if("Microsoft Corporation" >< offname){
     concluded = offname;
     offname = eregmatch(pattern:'([0-9.]+) .*Microsoft Corporation', string:offname);

      if(offname && offname[1] =~ "^(15|16)\."){
        offVer = "2016";
        location = "/Applications/Microsoft\ " + ver[0] + "/Contents/Info.plist";

        offVersion = offname[1];
        if(!offVersion){
          exit(0);
        }
      }
    }
  }
}

if(offVersion){
  set_kb_item(name:"MS/Office/MacOSX/Ver", value:offVersion);
  cpe = build_cpe(value:offVersion, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:office:" + offVer + "::mac:");
  if(isnull(cpe))
    cpe = "cpe:/a:microsoft:office:::mac";

  register_product(cpe:cpe, location:location);

  log_message(data:build_detection_report(app:"Microsoft Office " + offVer,
                                          version:offVersion,
                                          install:location,
                                          cpe:cpe,
                                          concluded:concluded));
}

close(sock);

# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800383");
  script_version("2019-04-22T07:09:02+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-22 07:09:02 +0000 (Mon, 22 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sun/Oracle Java Products Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Java Products.

  The script logs in via smb, searches for Java Products in the registry and
  gets the version from 'Version' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  adkeylist = make_list("SOFTWARE\JavaSoft\Java Runtime Environment\",
                        "SOFTWARE\JavaSoft\JRE\");
}else if("x64" >< osArch){
  adkeylist = make_list("SOFTWARE\JavaSoft\Java Runtime Environment\",
                        "SOFTWARE\JavaSoft\JRE\",
                        "SOFTWARE\Wow6432Node\JavaSoft\Java Runtime Environment\",
                        "SOFTWARE\Wow6432Node\JavaSoft\JRE\");
}

foreach jreKey(adkeylist){

  if(registry_key_exists(key:jreKey)){

    keys = registry_enum_keys(key:jreKey);
    foreach item(keys){

      if("JRE" >< jreKey && item =~ "^(9|10|11|12)"){
        pattern = "([0-9.]+)";
        flagjre9plus = TRUE;
      }else{
        pattern = "([0-9]+\.[0-9]+\.[0-9._]+)";
      }

      jreVer = eregmatch(pattern:pattern, string:item);
      if(jreVer[1]){
        JreTmpkey = jreKey + "\\"  + jreVer[1];
        path = registry_get_sz(key:JreTmpkey, item:"JavaHome");
        if(!path){
          path = "Could not find the install path from registry";
        }

        if(!isnull(jreVer[1])){

          set_kb_item(name:"Sun/Java/JRE/Win/Ver", value:jreVer[1]);
          set_kb_item(name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE);
          set_kb_item(name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE);
          if(flagjre9plus){
            jreVer_or = jreVer[1];
            ##Reset Flag
            flagjre9plus = FALSE;
          }else{

            jrVer = ereg_replace(pattern:"_|-", string:jreVer[1], replace:".");

            jreVer1 = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9]+)(\.([0-9]+))?", string:jrVer);
            if(jreVer1[1] && jreVer1[3]){
              jreVer_or = jreVer1[1] + ":update_" + jreVer1[3];
            }else if(jreVer1[1]){
              jreVer_or = jreVer1[1];
            }
          }

          if(version_is_less(version:jrVer, test_version:"1.4.2.38")||
             version_in_range(version:jrVer, test_version:"1.5", test_version2:"1.5.0.33")||
             version_in_range(version:jrVer, test_version:"1.6", test_version2:"1.6.0.18")){

            java_name = "Sun Java JRE 32-bit";
             ## (Before Oracles acquisition of Sun)
             cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:");
             if(isnull(cpe))
               cpe = "cpe:/a:sun:jre";

          }else{

            java_name = "Oracle Java JRE 32-bit";
            ## (After Oracles acquisition of Sun)
            cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:");
            if(isnull(cpe))
              cpe = "cpe:/a:oracle:jre";
          }

          if(!isnull(jreVer[1]) && "x64" >< osArch && "Wow6432Node" >!< jreKey){
            set_kb_item(name:"Sun/Java64/JRE64/Win/Ver", value:jreVer[1]);
            if(version_is_less(version:jrVer, test_version:"1.4.2.38")||
               version_in_range(version:jrVer, test_version:"1.5", test_version2:"1.5.0.33")||
               version_in_range(version:jrVer, test_version:"1.6", test_version2:"1.6.0.18")){

              java_name = "Sun Java JRE 64-bit";
              ## (Before Oracles acquisition of Sun)
              cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jre:x64:");
              if(isnull(cpe))
                cpe = "cpe:/a:sun:jre:x64";
            }else{

              java_name = "Oracle Java JRE 64-bit";
              ## (After Oracles acquisition of Sun)
              cpe = build_cpe(value:jreVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jre:x64:");
              if(isnull(cpe))
                cpe = "cpe:/a:oracle:jre:x64";
            }
          }
          # Used in gb_java_prdts_detect_portable_win.nasl to avoid doubled detections.
          # We're also stripping a possible ending backslash away as the portable NVT is getting
          # the file path without the ending backslash from WMI.
          tmp_location = tolower(path);
          tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
          set_kb_item(name:"Java/Win/InstallLocations", value:tmp_location);
          # This is a special case as the java.exe is placed within a "\bin" subdir
          set_kb_item(name:"Java/Win/InstallLocations", value:tmp_location + "\bin");
          register_and_report_cpe(app:java_name, ver:jreVer[1], cpename:cpe, insloc:path);
        }
      }
    }
  }
}

if("x86" >< osArch){
  adkeylist = make_list("SOFTWARE\JavaSoft\Java Development Kit",
                        "SOFTWARE\JavaSoft\JDK");
}else if("x64" >< osArch){
  adkeylist = make_list("SOFTWARE\JavaSoft\Java Development Kit",
                        "SOFTWARE\JavaSoft\JDK",
                        "SOFTWARE\Wow6432Node\JavaSoft\Java Development Kit",
                        "SOFTWARE\Wow6432Node\JavaSoft\JDK");
}

foreach jdkKey(adkeylist){

  if(registry_key_exists(key:jdkKey)){

    keys = registry_enum_keys(key:jdkKey);
    foreach item(keys){

      if("JDK" >< jdkKey && item =~ "^(9|10|11|12)"){
        pattern = "([0-9.]+)";
        flagjdk9plus = TRUE;
      }else{
        pattern = "([0-9]+\.[0-9]+\.[0-9._]+)";
      }

      jdkVer = eregmatch(pattern:pattern, string:item);
      if(jdkVer[1]){
        JdkTmpkey =  jdkKey + "\\"  + jdkVer[1];
        if(!registry_key_exists(key:JdkTmpkey)){
          path = "Could not find the install path from registry";
        }else{
          path = registry_get_sz(key:JdkTmpkey, item:"JavaHome");
          if(!path){
            path = "Could not find the install path from registry";
          }
        }

        if(!isnull(jdkVer[1])){

          set_kb_item(name:"Sun/Java/JDK/Win/Ver", value:jdkVer[1]);
          set_kb_item(name:"Sun/Java/JDK_or_JRE/Win/installed", value:TRUE);
          set_kb_item(name:"Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value:TRUE);

          if(flagjdk9plus){
            jdkVer_or = jdkVer[1];
            ##Reset Flag
            flagjdk9plus = FALSE;
          }else{

            jdVer = ereg_replace(pattern:"_|-", string:jdkVer[1], replace:".");

            jdkVer1 = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)", string:jdVer);
            jdkVer_or = jdkVer1[1] + ":update_" + jdkVer1[2];
          }

          if(version_is_less(version:jdVer, test_version:"1.4.2.38")||
             version_in_range(version:jdVer, test_version:"1.5", test_version2:"1.5.0.33")||
             version_in_range(version:jdVer, test_version:"1.6", test_version2:"1.6.0.18")){

            jdk_name= "Sun Java JDK 32-bit";
            ## (Before Oracles acquisition of Sun)
            cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jdk:");
            if(isnull(cpe))
              cpe = "cpe:/a:sun:jdk";
          }else{

            jdk_name = "Oracle Java JDK 32-bit";
            ## (After Oracles acquisition of Sun)
            cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jdk:");
            if(isnull(cpe))
              cpe = "cpe:/a:oracle:jdk";
          }

          if(!isnull(jdkVer[1]) && "x64" >< osArch && "Wow6432Node" >!< jdkKey){

            set_kb_item(name:"Sun/Java64/JDK64/Win/Ver", value:jdkVer[1]);

            if(version_is_less(version:jdVer, test_version:"1.4.2.38")||
               version_in_range(version:jdVer, test_version:"1.5", test_version2:"1.5.0.33")||
               version_in_range(version:jdVer, test_version:"1.6", test_version2:"1.6.0.18")){

              jdk_name = "Sun Java JDK 64-bit";
              ## (Before Oracles acquisition of Sun)
              cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:sun:jdk:x64:");
              if(isnull(cpe))
                cpe = "cpe:/a:sun:jdk:x64";
            }else{

              jdk_name = "Oracle Java JDK 64-bit";
              ## (After Oracles acquisition of Sun)
              cpe = build_cpe(value:jdkVer_or, exp:"^([:a-z0-9._]+)", base:"cpe:/a:oracle:jdk:x64:");
              if(isnull(cpe))
                cpe = "cpe:/a:oracle:jdk:x64";
            }
          }
          # Used in gb_java_prdts_detect_portable_win.nasl to avoid doubled detections.
          # We're also stripping a possible ending backslash away as the portable NVT is getting
          # the file path without the ending backslash from WMI.
          tmp_location = tolower(path);
          tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
          set_kb_item(name:"Java/Win/InstallLocations", value:tmp_location);
          # This is a special case as the java.exe is placed within a "\bin" subdir
          set_kb_item(name:"Java/Win/InstallLocations", value:tmp_location + "\bin");
          register_and_report_cpe(app:jdk_name, ver:jdkVer[1], cpename:cpe, insloc:path);
        }
      }
    }
  }
}

exit(0);

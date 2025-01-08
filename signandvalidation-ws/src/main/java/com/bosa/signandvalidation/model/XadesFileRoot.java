package com.bosa.signandvalidation.model;

import lombok.NoArgsConstructor;

import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@XmlRootElement(name = "root")
public class XadesFileRoot {

    private List<XadesFile> files = new ArrayList<XadesFile>();

    @XmlElement(name = "file")
    public List<XadesFile> getFiles() { return files; }

    public void setFiles(List<XadesFile> files) { this.files = files; }
}

/^- / {
    if (inblock == 1){
        print ""
    }
    inblock=0
    cont=0
}

/data:/ {
    if (index($0,"binary") == 0 ) {
        p = index($0, "data") - 1
        inblock=1
        printf("%*sdata: |-\n", p, "")
    }
}

{
    if (inblock == 1) {
        gsub(/^\s*data:\s+/,"")
        gsub(/^"/,"")
        gsub(/"$/,"")
        gsub(/\\"/,"\"")
        gsub(/^\s*/,"")
        n=split($0, a, /\\n/)
        s=1
        if (cont == 1) {
            printf(" %s\\r\\n\n",a[1])
            cont=0
            s=2
        }
        for (;s<n;++s) {
            printf("%*s%s\\r\\n\n",p+2,"",a[s])
        }
        if (length(a[s])) {
            printf("%*s%s",p+2,"",a[s])
            cont=1
        } 
    } else {
        print
    }
}



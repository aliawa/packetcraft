/^- / {
    inblock=0
}

/data:/ {
    if (index($0,"binary") == 0 ) {
        p = index($0, "data")
        inblock=1
        printf("%*sdata: |-\n", p, "")
    }
}

{
    if (inblock == 1) {
        gsub(/"/,"")
        gsub(/^\s*data:\s+/,"")
        gsub(/^\s*/,"")
        split($0, a, /\\n/)
        for (s in a){
            if (length(a[s])){
                printf("%*s%s\\r\\n\n",p+2,"",a[s])
            }
        }
    } else {
        print
    }
}



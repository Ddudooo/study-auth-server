package study.spring.studyauthserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class StudyAuthServerApplication

fun main(args: Array<String>) {
    runApplication<StudyAuthServerApplication>(*args)
}

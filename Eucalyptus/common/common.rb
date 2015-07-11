class Eucalyptus
    def which_threads
        if threads.size == 1
            pid = threads[0].to_i
            return
        end

        puts "Thread IDs:"
        threads.each { |h| puts h }
        puts "Which thread ID do you want to trace?"
        pid = STDIN.gets.chomp.to_i
    end
end
